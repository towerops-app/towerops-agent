// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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

// osExit is a var so tests can intercept the rollback path's exit.
var osExit = os.Exit

// jsonMarshal is a seam so tests can fail the update result encode.
var jsonMarshal = json.Marshal

// updateJoinTimeout bounds how long a freshly replaced binary may run without
// joining its channel before the startup guard restores the previous build.
// Reaching the guard at all means the binary booted; staying offline past the
// window is treated as a failed update, not a flaky link, because the agent
// still cannot do its job (issue #2736).
var updateJoinTimeout = 120 * time.Second

// maxUpdateBootAttempts bounds the crash-loop case: a build that dies before
// arming the watchdog still increments its own attempt counter at startup, so
// repeated crashes converge on a rollback instead of restarting forever.
const maxUpdateBootAttempts = 3

// pendingUpdate is the marker file written beside the binary before re-exec.
// It survives the exec, so the next boot knows it is running an unproven build.
type pendingUpdate struct {
	Version  string `json:"version"`
	Attempts int    `json:"attempts"`
}

// updateResult is the outcome file the heartbeat reports to the server. It
// lives next to the binary so the re-execd process, or the process that ran
// before a failed exec, both find it at the same path.
type updateResult struct {
	TargetVersion string `json:"target_version"`
	Error         string `json:"error"`
	AttemptedAt   int64  `json:"attempted_at"`
}

var updateAttemptedAtUnix = time.Now

// pendingUpdatePath locates the marker beside the executable. The path is a
// var so tests can point it at a temp dir without an osExecutable stub.
var pendingUpdatePath = func() (string, error) {
	exe, err := osExecutable()
	if err != nil {
		return "", err
	}
	return exe + ".update-pending", nil
}

var updateResultPath = func() (string, error) {
	exe, err := osExecutable()
	if err != nil {
		return "", err
	}
	return exe + ".update-result", nil
}

// readUpdateResult returns the last recorded outcome, or nil when the agent
// has never completed an update attempt since this build shipped.
func readUpdateResult() *updateResult {
	path, err := updateResultPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	res := &updateResult{}
	if err := json.Unmarshal(data, res); err != nil {
		return nil
	}
	return res
}

// writeUpdateResult persists an outcome so heartbeat reports survive re-exec.
// Failure is logged, not propagated: reporting must never break the update
// path or the reconnect loop it runs inside.
func writeUpdateResult(res updateResult) {
	path, err := updateResultPath()
	if err != nil {
		slog.Warn("cannot resolve update result path", "error", err)
		return
	}
	data, err := jsonMarshal(res)
	if err != nil {
		slog.Warn("cannot encode update result", "error", err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		slog.Warn("cannot write update result", "path", path, "error", err)
	}
}

// recordUpdateFailure stamps a failed attempt. The agent reports it on the
// next heartbeat; a box that cannot reach the server at all keeps the file
// until it can.
func recordUpdateFailure(version string, err error) {
	writeUpdateResult(updateResult{
		TargetVersion: version,
		Error:         err.Error(),
		AttemptedAt:   updateAttemptedAtUnix().Unix(),
	})
}

// recordUpdateSuccess clears the failure state: the last attempt applied, so
// the result carries an empty error and the server resets its offer budget.
func recordUpdateSuccess(version string, attemptedAt int64) {
	writeUpdateResult(updateResult{
		TargetVersion: version,
		Error:         "",
		AttemptedAt:   attemptedAt,
	})
}

// updateWatchdog is the running-join timer for an unproven build. Exactly one
// pending update can be armed at a time.
var updateWatchdog atomic.Pointer[time.Timer]

// armedUpdate is the unproven build the watchdog guards, read back by
// updateJoined when a session proves it.
var armedUpdate atomic.Pointer[pendingUpdate]

// checkPendingUpdate runs at startup. With no marker it is a no-op. With a
// marker it counts this boot as an attempt of the unproven build: past the
// crash-loop bound it restores the previous binary immediately, otherwise it
// arms the watchdog that rolls back if no session joins in time. It returns
// the pending record so the caller can finish cleanup on a successful join.
func checkPendingUpdate() *pendingUpdate {
	path, err := pendingUpdatePath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	p := &pendingUpdate{}
	if err := json.Unmarshal(data, p); err != nil {
		slog.Warn("removing unreadable update marker", "path", path, "error", err)
		_ = os.Remove(path)
		return nil
	}

	p.Attempts++
	if p.Attempts > maxUpdateBootAttempts {
		slog.Error("updated binary crashed before joining repeatedly; restoring previous build",
			"version", p.Version, "attempts", p.Attempts)
		rollbackUpdate(fmt.Sprintf("updated binary failed to join within %d boots", maxUpdateBootAttempts))
		osExit(1)
		return nil
	}

	if err := os.WriteFile(path, mustJSON(p), 0600); err != nil {
		slog.Warn("cannot update attempt count in update marker", "path", path, "error", err)
	}

	timer := time.AfterFunc(updateJoinTimeout, func() {
		slog.Error("updated binary did not join its channel; restoring previous build",
			"version", p.Version, "timeout", updateJoinTimeout)
		rollbackUpdate(fmt.Sprintf("updated binary did not join its channel within %s", updateJoinTimeout))
		osExit(1)
	})
	updateWatchdog.Store(timer)
	armedUpdate.Store(p)
	return p
}

// updateJoined clears the pending state once a session join proves the new
// build works: the watchdog is stopped, the marker removed, and success
// recorded for the heartbeat. With nothing armed it is a no-op.
func updateJoined() {
	p := armedUpdate.Swap(nil)
	if p == nil {
		return
	}
	if timer := updateWatchdog.Swap(nil); timer != nil {
		timer.Stop()
	}
	if path, err := pendingUpdatePath(); err == nil {
		_ = os.Remove(path)
	}
	recordUpdateSuccess(p.Version, updateAttemptedAtUnix().Unix())
	slog.Info("self-update verified: session joined", "version", p.Version)
}

// rollbackUpdate restores the previous binary over the unproven one and
// records the failure so the heartbeat that eventually runs reports it.
// The marker is removed regardless: whatever happens next boot must not be
// treated as still-unproven.
func rollbackUpdate(reason string) {
	exe, err := osExecutable()
	if err != nil {
		slog.Error("cannot resolve executable for update rollback", "error", err)
		return
	}
	prev := exe + ".prev"
	path, perr := pendingUpdatePath()
	var pending pendingUpdate
	if perr == nil {
		if data, rerr := os.ReadFile(path); rerr == nil {
			_ = json.Unmarshal(data, &pending)
		}
		_ = os.Remove(path)
	}
	if timer := updateWatchdog.Swap(nil); timer != nil {
		timer.Stop()
	}
	armedUpdate.Store(nil)
	if err := osRename(prev, exe); err != nil {
		slog.Error("update rollback failed: cannot restore previous binary",
			"prev", prev, "error", err)
		recordUpdateFailure(pending.Version, fmt.Errorf("%s; rollback failed: %w", reason, err))
		return
	}
	if err := syncDirectory(filepath.Dir(exe)); err != nil {
		slog.Warn("fsync after update rollback failed", "error", err)
	}
	slog.Warn("restored previous agent binary after failed update", "reason", reason)
	recordUpdateFailure(pending.Version, errors.New(reason))
}

// validateStagedBinary rejects a staged download that cannot execute here:
// anything that is not a real ELF executable for this machine's architecture
// must fail before the running binary is touched, not after (issue #2736).
// Builds whose GOARCH has no ELF mapping (darwin test hosts run the binary
// fine; the check matters for linux releases) skip the arch check only.
func validateStagedBinary(path, goarch string) error {
	f, err := elfOpen(path)
	if err != nil {
		return fmt.Errorf("staged update is not an executable binary: %w", err)
	}
	defer func() { _ = f.Close() }()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("staged update is not an executable binary (ELF type %s)", f.Type)
	}
	want, ok := elfMachineForGOARCH(goarch)
	if !ok {
		return nil
	}
	if f.Machine != want {
		return fmt.Errorf("staged update is for %s, this agent runs %s", f.Machine, want)
	}
	return nil
}

var elfOpen = elf.Open

func elfMachineForGOARCH(goarch string) (elf.Machine, bool) {
	switch goarch {
	case "amd64":
		return elf.EM_X86_64, true
	case "386":
		return elf.EM_386, true
	case "arm64":
		return elf.EM_AARCH64, true
	case "arm":
		return elf.EM_ARM, true
	case "riscv64":
		return elf.EM_RISCV, true
	default:
		return elf.EM_NONE, false
	}
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return data
}

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

// selfUpdateContext downloads a new binary, verifies its checksum and that it
// is an executable for this machine, replaces the current binary, and
// re-execs while honoring caller cancellation. The running binary is first
// moved aside as <exe>.prev and an update-pending marker is written before
// exec, so a build that never joins its channel is rolled back on startup
// rather than left crash-looping (issue #2736). version is the release the
// server targeted; it labels the reported outcome.
func selfUpdateContext(ctx context.Context, downloadURL, expectedChecksum, version string) error {
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
	// A completed read or local file operation may succeed after cancellation.
	// Honor the request before committing the staged binary to disk.
	if cause := context.Cause(reqCtx); cause != nil {
		return fmt.Errorf("update canceled before replacement: %w", cause)
	}

	// A wrong-architecture or non-executable download must be refused here,
	// while the running binary is still untouched.
	if err := validateStagedBinary(tempPath, runtime.GOARCH); err != nil {
		return fmt.Errorf("rejecting staged update: %w", err)
	}

	// Keep the running build restorable: move it aside, put the staged build
	// in place, and mark the update pending so the next boot knows the binary
	// under the executable path is unproven. An exec that fails below leaves
	// everything it changed reversible from this same process.
	prevExe := currentExe + ".prev"
	if err := osRename(currentExe, prevExe); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}
	if err := osRename(tempPath, currentExe); err != nil {
		// The staged build failed to land; put the running one back.
		if restoreErr := osRename(prevExe, currentExe); restoreErr != nil {
			return fmt.Errorf("rename new binary: %w (and restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("rename new binary: %w", err)
	}
	slog.Warn("replaced binary does not inherit file capabilities granted with setcap", "path", currentExe)

	markerPath, err := pendingUpdatePath()
	if err != nil {
		markerPath = currentExe + ".update-pending"
	}
	marker := pendingUpdate{Version: version, Attempts: 0}
	if err := os.WriteFile(markerPath, mustJSON(marker), 0600); err != nil {
		slog.Warn("cannot write update-pending marker; a bad build cannot self-recover",
			"path", markerPath, "error", err)
	}

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
	execErr := syscallExec(currentExe, os.Args, os.Environ())
	if execErr == nil {
		// A real syscall.Exec never returns; a nil return means the caller
		// stubbed it and the process is considered replaced.
		return nil
	}

	// Only an exec failure reaches here: the staged build never ran, so this
	// process is still the working one. Restore the previous binary, drop the
	// marker it would trip over next boot, and surface the error.
	slog.Error("re-exec of updated binary failed; restoring previous build",
		"path", currentExe, "error", execErr)
	if restoreErr := osRename(prevExe, currentExe); restoreErr != nil {
		slog.Error("restore of previous binary failed", "error", restoreErr)
	}
	_ = os.Remove(markerPath)
	return fmt.Errorf("re-exec updated binary: %w", execErr)
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
