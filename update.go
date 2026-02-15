package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var osExecutable = os.Executable
var osCreateTemp = os.CreateTemp
var osRename = os.Rename
var httpGet = http.Get
var maxUpdateSize int64 = 100 << 20 // 100 MB

// selfUpdate downloads a new binary, verifies its checksum, replaces the current binary, and re-execs.
func selfUpdate(downloadURL, expectedChecksum string) error {
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

	slog.Info("downloading update", "url", downloadURL)

	resp, err := httpGet(downloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpdateSize+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxUpdateSize {
		return fmt.Errorf("download size %d exceeds max %d", len(body), maxUpdateSize)
	}
	slog.Info("downloaded update", "bytes", len(body))

	// Verify SHA256 checksum (constant-time comparison)
	actual := fmt.Sprintf("%x", sha256.Sum256(body))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedChecksum)) != 1 {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actual)
	}
	slog.Info("checksum verified")

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
	defer func() { _ = os.Remove(tempPath) }() // cleanup on any failure

	if _, err := tempFile.Write(body); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tempFile.Chmod(0700); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	// Re-verify checksum by reading back the written file
	written, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf("re-read temp: %w", err)
	}
	recheck := fmt.Sprintf("%x", sha256.Sum256(written))
	if subtle.ConstantTimeCompare([]byte(recheck), []byte(expectedChecksum)) != 1 {
		return fmt.Errorf("re-verify checksum mismatch: expected %s, got %s", expectedChecksum, recheck)
	}
	slog.Info("re-verified checksum after write")

	// Replace current binary (atomic on same filesystem)
	if err := osRename(tempPath, currentExe); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	slog.Info("binary replaced", "path", currentExe)

	// Re-exec with same arguments
	slog.Info("re-executing", "args", sanitizeArgs(os.Args))
	return syscall.Exec(currentExe, os.Args, os.Environ())
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
