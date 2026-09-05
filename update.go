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
var maxUpdateSize int64 = 100 << 20 // 100 MB

var containerMarkerFiles = []string{"/.dockerenv", "/run/.containerenv"}
var containerCgroupPath = "/proc/1/cgroup"

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
	if err != nil {
		return false
	}
	cgroups := string(cgroup)
	return strings.Contains(cgroups, "docker") ||
		strings.Contains(cgroups, "containerd") ||
		strings.Contains(cgroups, "kubepods") ||
		strings.Contains(cgroups, "libpod")
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

	// Re-exec with same arguments
	slog.Info("re-executing", "args", sanitizeArgs(os.Args))
	return syscallExec(currentExe, os.Args, os.Environ())
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// sanitizeArgs returns a copy of args with token values masked.
func sanitizeArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if (a == "--token" || a == "-token") && i+1 < len(out) {
			out[i+1] = "***"
		} else if strings.HasPrefix(a, "--token=") || strings.HasPrefix(a, "-token=") {
			out[i] = a[:strings.Index(a, "=")+1] + "***"
		}
	}
	return out
}
