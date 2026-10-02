// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var osExecutable = os.Executable

// updateTempFile is the subset of *os.File used to stage a downloaded update.
// It is an interface so tests can inject chmod/sync/close failures, which no
// real file produces deterministically.
type updateTempFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

var osCreateTemp = func(dir, pattern string) (updateTempFile, error) {
	return os.CreateTemp(dir, pattern)
}
var osRename = os.Rename
var httpNewRequest = http.NewRequestWithContext
var httpDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}
var syscallExec = syscall.Exec

// drainResultSpool bounds how long the update path waits for the result spool
// to flush before re-exec. It holds a func(ctx context.Context) bool reporting
// whether the spool emptied in time; the agent/session layer registers it once
// a resultQueue exists. No hook means nothing is drained — exec proceeds
// unchanged.
var drainResultSpool atomic.Pointer[func(context.Context) bool]

// spoolDrainTimeout bounds the drain so a stalled session cannot delay the
// upgrade indefinitely.
var spoolDrainTimeout = 5 * time.Second
var maxUpdateSize int64 = 100 << 20 // 100 MB

var containerMarkerFiles = []string{"/.dockerenv", "/run/.containerenv"}
var containerCgroupPath = "/proc/1/cgroup"
var containerCgroupNamespacePath = "/proc/1/ns/cgroup"
var containerMountInfoPath = "/proc/self/mountinfo"

// Linux exposes the initial cgroup namespace with this reserved proc inode.
const initialCgroupNamespace = "cgroup:[4026531835]"

// runningInContainer reports whether the agent runs inside a container image,
// where the binary cannot be replaced in place. Result is computed once.
var runningInContainer = sync.OnceValue(detectContainer)

func detectContainer() bool {
	for _, path := range containerMarkerFiles {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	cgroup, err := os.ReadFile(containerCgroupPath)
	if err == nil &&
		(containsContainerEvidence(cgroup) || cgroupRootInPrivateNamespace(cgroup)) {
		return true
	}

	mountInfo, err := os.ReadFile(containerMountInfoPath)
	return err == nil && rootIsOverlay(mountInfo)
}

func containsContainerEvidence(data []byte) bool {
	text := string(data)
	return strings.Contains(text, "docker") ||
		strings.Contains(text, "containerd") ||
		strings.Contains(text, "kubepods") ||
		strings.Contains(text, "libpod")
}

func cgroupRootInPrivateNamespace(data []byte) bool {
	if strings.TrimSpace(string(data)) != "0::/" {
		return false
	}
	namespace, err := os.Readlink(containerCgroupNamespacePath)
	return err == nil && namespace != initialCgroupNamespace
}

func rootIsOverlay(mountInfo []byte) bool {
	for line := range strings.SplitSeq(string(mountInfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != "/" {
			continue
		}
		for i, field := range fields {
			if field == "-" && i+1 < len(fields) {
				return strings.Contains(fields[i+1], "overlay")
			}
		}
	}
	return false
}

// The response-header budget is separate from the transfer watchdog so a
// progressing download is not rejected solely because the link is slow.
var selfUpdateTimeout = 30 * time.Second
var selfUpdateIdleTimeout = 30 * time.Second
var errSelfUpdateIdleTimeout = errors.New("update download idle timeout")

// errSelfUpdateInContainer explains a refusal the operator would otherwise see
// as "create temp: permission denied": /usr/local/bin is root-owned in the
// image, and even a writable directory would leave the replacement binary
// without the cap_net_raw/cap_net_bind_service the image grants with setcap.
var errSelfUpdateInContainer = errors.New(
	"self-update unsupported in this deployment: the agent runs in a container image; update by pulling a new image")

type updateIdleReader struct {
	reader  io.Reader
	timer   *time.Timer
	timeout time.Duration
}

func (r *updateIdleReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.timer.Reset(r.timeout)
	}
	return n, err
}

// selfUpdateContext downloads a new binary, verifies its checksum, replaces
// the current binary, and re-execs while honoring caller cancellation.
func selfUpdateContext(ctx context.Context, downloadURL, expectedChecksum string) error {
	if runningInContainer() {
		return errSelfUpdateInContainer
	}

	u, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("HTTPS required for update URL, got %q", u.Scheme)
	}
	if expectedChecksum == "" {
		return fmt.Errorf("checksum required for update")
	}
	expected, err := hex.DecodeString(expectedChecksum)
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("checksum must be exactly 64 hexadecimal characters")
	}
	slog.Info("downloading update", "url", sanitizeURL(downloadURL))

	reqCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	req, err := httpNewRequest(reqCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	headerTimer := time.AfterFunc(selfUpdateTimeout, func() {
		cancel(context.DeadlineExceeded)
	})

	resp, err := httpDo(req)
	headersInTime := headerTimer.Stop()
	if !headersInTime {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("download: %w", context.DeadlineExceeded)
	}
	if err != nil {
		if cause := context.Cause(reqCtx); cause != nil {
			return fmt.Errorf("download: %w", cause)
		}
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Scheme != "https" {
		return fmt.Errorf("HTTPS required after redirects")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Write to temp file in same directory as binary (ensures same filesystem for atomic rename)
	currentExe, err := osExecutable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	tempFile, err := osCreateTemp(filepath.Dir(currentExe), ".towerops-update-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()

	hash := sha256.New()
	idleReader := &updateIdleReader{
		reader:  resp.Body,
		timeout: selfUpdateIdleTimeout,
	}
	idleReader.timer = time.AfterFunc(selfUpdateIdleTimeout, func() {
		cancel(errSelfUpdateIdleTimeout)
	})
	written, err := io.Copy(io.MultiWriter(tempFile, hash), io.LimitReader(idleReader, maxUpdateSize+1))
	idleReader.timer.Stop()
	if err != nil {
		_ = tempFile.Close()
		if errors.Is(context.Cause(reqCtx), errSelfUpdateIdleTimeout) {
			return fmt.Errorf("download update: %w", errSelfUpdateIdleTimeout)
		}
		return fmt.Errorf("download update: %w", err)
	}
	if written > maxUpdateSize {
		_ = tempFile.Close()
		return fmt.Errorf("download size %d exceeds max %d", written, maxUpdateSize)
	}
	actual := hash.Sum(nil)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		_ = tempFile.Close()
		return fmt.Errorf("checksum mismatch: expected %s, got %x", expectedChecksum, actual)
	}
	slog.Info("downloaded and verified update", "bytes", written)

	if err := tempFile.Chmod(0700); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	// Replace current binary (atomic on same filesystem)
	if err := osRename(tempPath, currentExe); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	slog.Warn("replaced binary does not inherit file capabilities granted with setcap", "path", currentExe)
	if err := syncDirectory(filepath.Dir(currentExe)); err != nil {
		return fmt.Errorf("sync executable directory: %w", err)
	}
	slog.Info("binary replaced", "path", currentExe)

	// Flush spooled results before exec discards the process: the drain
	// hook stops the session accepting new jobs and waits for the queue to
	// empty. Bounded so a stalled session cannot stall the upgrade.
	if drain := drainResultSpool.Load(); drain != nil {
		drainCtx, drainCancel := context.WithTimeout(ctx, spoolDrainTimeout)
		drained := (*drain)(drainCtx)
		drainCancel()
		if !drained {
			slog.Warn("self-update drain timed out; spooled results and in-flight jobs are discarded by re-exec")
		}
	}

	// Re-exec with same arguments
	slog.Info("re-executing", "args", sanitizeArgs(os.Args))
	return syscallExec(currentExe, os.Args, os.Environ())
}

// syncDirectory is a var so tests can fail the post-rename fsync.
var syncDirectory = syncDir

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// sanitizeArgs returns a copy of args with the values of flags that carry
// secrets masked, so os.Args can be logged during re-exec without leaking
// credentials.
func sanitizeArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if sensitiveArg(a) && i+1 < len(out) {
			out[i+1] = "***"
		} else if name, _, found := strings.Cut(a, "="); found && sensitiveArg(name) {
			out[i] = name + "=***"
		}
	}
	return out
}

// sensitiveArg reports whether a is a flag whose value is a secret. The flag's
// value must never reach the logs, whether given as "--flag value" or
// "--flag=value".
func sensitiveArg(a string) bool {
	for _, name := range []string{"token", "trap-community"} {
		if a == "--"+name || a == "-"+name {
			return true
		}
	}
	return false
}
