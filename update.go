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
	"syscall"
)

var osExecutable = os.Executable
var osWriteFile = os.WriteFile
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

	// Write to temp file next to current binary
	currentExe, err := osExecutable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	tempPath := currentExe + ".update"

	if err := osWriteFile(tempPath, body, 0755); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}

	// Replace current binary
	if err := osRename(tempPath, currentExe); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename: %w", err)
	}
	slog.Info("binary replaced", "path", currentExe)

	// Re-exec with same arguments
	slog.Info("re-executing", "args", os.Args)
	return syscall.Exec(currentExe, os.Args, os.Environ())
}
