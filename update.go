// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var osExecutable = os.Executable
var osCreateTemp = os.CreateTemp
var osRename = os.Rename
var httpDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}
var syscallExec = syscall.Exec
var maxUpdateSize int64 = 100 << 20 // 100 MB
var selfUpdateTimeout = 30 * time.Second

// selfUpdate downloads a new binary, verifies its checksum, replaces the current binary, and re-execs.
func selfUpdate(downloadURL, expectedChecksum string) error {
	return selfUpdateContext(context.Background(), downloadURL, expectedChecksum)
}

func selfUpdateContext(ctx context.Context, downloadURL, expectedChecksum string) error {
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
	slog.Info("downloading update", "url", sanitizeURL(downloadURL))

	reqCtx, cancel := context.WithTimeout(ctx, selfUpdateTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := httpDo(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Scheme != "https" {
		return fmt.Errorf("HTTPS required after redirects")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}
	expected, err := hex.DecodeString(expectedChecksum)
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("checksum must be exactly 64 hexadecimal characters")
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
	written, err := io.Copy(io.MultiWriter(tempFile, hash), io.LimitReader(resp.Body, maxUpdateSize+1))
	if err != nil {
		_ = tempFile.Close()
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
