package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"syscall"
)

// selfUpdate downloads a new binary, verifies its checksum, replaces the current binary, and re-execs.
func selfUpdate(downloadURL, expectedChecksum string) error {
	slog.Info("downloading update", "url", downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	slog.Info("downloaded update", "bytes", len(body))

	// Verify SHA256 checksum
	if expectedChecksum != "" {
		actual := fmt.Sprintf("%x", sha256.Sum256(body))
		if actual != expectedChecksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actual)
		}
		slog.Info("checksum verified")
	}

	// Write to temp file next to current binary
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	tempPath := currentExe + ".update"

	if err := os.WriteFile(tempPath, body, 0755); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}

	// Replace current binary
	if err := os.Rename(tempPath, currentExe); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename: %w", err)
	}
	slog.Info("binary replaced", "path", currentExe)

	// Re-exec with same arguments
	slog.Info("re-executing", "args", os.Args)
	return syscall.Exec(currentExe, os.Args, os.Environ())
}
