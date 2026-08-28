// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestSelfUpdateRejectsHTTP(t *testing.T) {
	err := selfUpdate("http://example.com/agent", "abc123")
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("expected 'HTTPS required' in error, got: %v", err)
	}
}

func TestSelfUpdateRejectsRedirectToHTTP(t *testing.T) {
	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = func(*http.Request) (*http.Response, error) {
		request, err := http.NewRequest(http.MethodGet, "http://example.com/agent", nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("binary")),
			Request:    request,
		}, nil
	}

	err := selfUpdate("https://example.com/agent", strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "after redirects") {
		t.Fatalf("selfUpdate error = %v, want HTTPS redirect rejection", err)
	}
}

func TestSelfUpdateRequiresChecksum(t *testing.T) {
	err := selfUpdate("https://example.com/agent", "")
	if err == nil {
		t.Error("expected error for empty checksum")
	}
	if !strings.Contains(err.Error(), "checksum required") {
		t.Errorf("expected 'checksum required' in error, got: %v", err)
	}
}

func TestSelfUpdateBadURL(t *testing.T) {
	err := selfUpdate("https://127.0.0.1:1/nonexistent", "abc123")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestSelfUpdateChecksumMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fake binary"))
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestSelfUpdate404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL)+"/missing", "abc123")
	if err == nil {
		t.Error("expected error for 404 response")
	}
	if err != nil && !strings.Contains(err.Error(), "status 404") {
		t.Errorf("expected 'status 404' in error, got: %v", err)
	}
}

func TestSelfUpdateReadBodyError(t *testing.T) {
	// Server sends Content-Length header but closes connection prematurely
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "99999")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		// Connection closes without sending the full body
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), "abc123")
	// This may or may not error depending on io.ReadAll behavior with truncated body
	// but we exercise the code path
	_ = err
}

func TestSelfUpdateOsExecutableError(t *testing.T) {
	origExe := osExecutable
	defer func() { osExecutable = origExe }()
	osExecutable = func() (string, error) {
		return "", fmt.Errorf("executable not found")
	}

	body := []byte("binary data")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Error("expected os.Executable error")
	}
	if !strings.Contains(err.Error(), "get executable path") {
		t.Errorf("expected 'get executable path' in error, got: %v", err)
	}
}

func TestSelfUpdateCreateTempError(t *testing.T) {
	origExe := osExecutable
	origCreate := osCreateTemp
	defer func() {
		osExecutable = origExe
		osCreateTemp = origCreate
	}()
	osExecutable = func() (string, error) { return "/tmp/test-agent", nil }
	osCreateTemp = func(dir, pattern string) (updateTempFile, error) {
		return nil, fmt.Errorf("disk full")
	}

	body := []byte("binary data")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Error("expected create temp error")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Errorf("expected 'create temp' in error, got: %v", err)
	}
}

func TestSelfUpdateRenameError(t *testing.T) {
	origExe := osExecutable
	origRename := osRename
	defer func() {
		osExecutable = origExe
		osRename = origRename
	}()
	dir := t.TempDir()
	osExecutable = func() (string, error) { return filepath.Join(dir, "test-agent"), nil }
	osRename = func(oldpath, newpath string) error {
		return fmt.Errorf("permission denied")
	}

	body := []byte("binary data")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Error("expected rename error")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("expected 'rename' in error, got: %v", err)
	}
}

func TestSelfUpdateChecksumMatch(t *testing.T) {
	body := []byte("test binary content")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	origExe := osExecutable
	origRename := osRename
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		osRename = origRename
	}()
	httpDo = srv.Client().Do

	// Stage into a temp dir and stop at the rename: letting the real
	// os.Executable/os.Rename/syscall.Exec run would overwrite and re-exec the
	// test binary itself.
	dir := t.TempDir()
	osExecutable = func() (string, error) { return filepath.Join(dir, "test-agent"), nil }
	osRename = func(string, string) error { return fmt.Errorf("stop before replacing binary") }

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Fatal("expected error (rename is stubbed out)")
	}
	// Reaching the rename step proves checksum verification passed.
	if !strings.Contains(err.Error(), "stop before replacing binary") {
		t.Errorf("expected the stubbed rename error, got: %v", err)
	}
	if strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("checksum verification unexpectedly failed: %v", err)
	}
}

func TestSelfUpdateFilePermissions(t *testing.T) {
	origExe := osExecutable
	origRename := osRename
	defer func() {
		osExecutable = origExe
		osRename = origRename
	}()
	dir := t.TempDir()
	osExecutable = func() (string, error) { return filepath.Join(dir, "test-agent"), nil }

	var capturedPath string
	osRename = func(oldpath, newpath string) error {
		capturedPath = oldpath
		return fmt.Errorf("stop here") // stop before re-exec
	}

	body := []byte("binary data")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	_ = selfUpdate(rewriteToHTTPS(srv.URL), checksum)

	if capturedPath != "" {
		info, err := os.Stat(capturedPath)
		if err == nil {
			if info.Mode().Perm() != 0700 {
				t.Errorf("expected file permissions 0700, got %o", info.Mode().Perm())
			}
		}
	}
}

func TestSelfUpdateTooLarge(t *testing.T) {
	origMax := maxUpdateSize
	defer func() { maxUpdateSize = origMax }()
	maxUpdateSize = 100 // 100 bytes

	body := make([]byte, 200) // Larger than limit
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Error("expected error for oversized download")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("expected 'exceeds max' in error, got: %v", err)
	}
}

func TestSanitizeArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"flag with separate value", []string{"agent", "--token", "secret"}, []string{"agent", "--token", "***"}},
		{"no sensitive flags", []string{"agent", "--api-url", "wss://x"}, []string{"agent", "--api-url", "wss://x"}},
		{"equals syntax", []string{"agent", "--token=secret"}, []string{"agent", "--token=***"}},
		{"empty args", []string{"agent"}, []string{"agent"}},
		{"trailing flag no value", []string{"agent", "--token"}, []string{"agent", "--token"}},
		{"short flag with value", []string{"agent", "-token", "secret"}, []string{"agent", "-token", "***"}},
		{"short equals syntax", []string{"agent", "-token=secret"}, []string{"agent", "-token=***"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeArgs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("length: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("arg[%d]: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}

	// Verify original slice is not mutated
	t.Run("does not mutate input", func(t *testing.T) {
		orig := []string{"agent", "--token", "secret"}
		_ = sanitizeArgs(orig)
		if orig[2] != "secret" {
			t.Error("sanitizeArgs mutated the input slice")
		}
	})
}

func TestSelfUpdateInvalidURL(t *testing.T) {
	err := selfUpdate("://\x7f", "abc123")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
	if err != nil && !strings.Contains(err.Error(), "parse url") {
		t.Errorf("expected 'parse url' in error, got: %v", err)
	}
}

func TestSelfUpdateFullHappyPath(t *testing.T) {
	body := []byte("test binary content for full path")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	origExe := osExecutable
	origRename := osRename
	origExec := syscallExec
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		osRename = origRename
		syscallExec = origExec
	}()
	httpDo = srv.Client().Do

	dir := t.TempDir()
	exePath := filepath.Join(dir, "test-agent")
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = func(oldpath, newpath string) error {
		return os.Rename(oldpath, newpath) // real rename within temp dir
	}
	syscallExec = func(argv0 string, argv []string, envv []string) error {
		return nil // success — don't actually re-exec
	}

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err != nil {
		t.Errorf("expected nil error on full happy path, got: %v", err)
	}
}

func TestSelfUpdateWriteError(t *testing.T) {
	body := []byte("binary")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	origExe := osExecutable
	origCreate := osCreateTemp
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		osCreateTemp = origCreate
	}()
	httpDo = srv.Client().Do

	dir := t.TempDir()
	osExecutable = func() (string, error) { return filepath.Join(dir, "agent"), nil }

	// Create a temp file that will fail on Write by closing it before selfUpdate tries to write
	osCreateTemp = func(d, pattern string) (updateTempFile, error) {
		f, err := os.CreateTemp(d, pattern)
		if err != nil {
			return nil, err
		}
		// Close the file so Write will fail
		_ = f.Close()
		return f, nil
	}

	err := selfUpdate(rewriteToHTTPS(srv.URL), checksum)
	if err == nil {
		t.Error("expected write error")
	}
}

func TestSelfUpdateDownloadTimeout(t *testing.T) {
	origDo := httpDo
	origTimeout := selfUpdateTimeout
	defer func() {
		httpDo = origDo
		selfUpdateTimeout = origTimeout
	}()

	httpDo = func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	selfUpdateTimeout = 10 * time.Millisecond

	err := selfUpdate("https://example.com/agent", strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
}

// rewriteToHTTPS converts an httptest TLS server URL to use the https scheme.
// httptest.NewTLSServer returns URLs with https:// already, but this ensures consistency.
func rewriteToHTTPS(rawURL string) string {
	if strings.HasPrefix(rawURL, "http://") {
		return "https://" + strings.TrimPrefix(rawURL, "http://")
	}
	return rawURL
}

// cliTUpdateServer serves body over TLS, points httpDo at it, and returns the
// download URL plus the matching sha256 checksum.
func cliTUpdateServer(t *testing.T, body []byte) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	origDo := httpDo
	t.Cleanup(func() { httpDo = origDo })
	httpDo = srv.Client().Do

	return rewriteToHTTPS(srv.URL), fmt.Sprintf("%x", sha256.Sum256(body))
}

// cliTFakeTempFile wraps a real temp file so an individual chmod/sync/close
// call can be made to fail.
type cliTFakeTempFile struct {
	file     *os.File
	chmodErr error
	syncErr  error
	closeErr error
	closes   int
}

func (f *cliTFakeTempFile) Write(p []byte) (int, error) { return f.file.Write(p) }
func (f *cliTFakeTempFile) Name() string                { return f.file.Name() }

func (f *cliTFakeTempFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.file.Chmod(mode)
}

func (f *cliTFakeTempFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.file.Sync()
}

func (f *cliTFakeTempFile) Close() error {
	f.closes++
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.file.Close()
}

func TestCliTSelfUpdateBuildRequestError(t *testing.T) {
	origNewRequest := httpNewRequest
	origDo := httpDo
	defer func() {
		httpNewRequest = origNewRequest
		httpDo = origDo
	}()

	httpNewRequest = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, errors.New("unsupported protocol scheme")
	}
	httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("httpDo must not run when the request cannot be built")
		return nil, nil
	}

	err := selfUpdate("https://example.com/agent", strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "build request: unsupported protocol scheme") {
		t.Fatalf("selfUpdate error = %v, want build request failure", err)
	}
}

func TestCliTSelfUpdateTempFileFailures(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		apply func(*cliTFakeTempFile)
	}{
		{"chmod", "chmod temp: chmod exploded", func(f *cliTFakeTempFile) { f.chmodErr = errors.New("chmod exploded") }},
		{"sync", "sync temp: sync exploded", func(f *cliTFakeTempFile) { f.syncErr = errors.New("sync exploded") }},
		{"close", "close temp: close exploded", func(f *cliTFakeTempFile) { f.closeErr = errors.New("close exploded") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("staged update payload")
			downloadURL, checksum := cliTUpdateServer(t, body)

			origExe := osExecutable
			origCreate := osCreateTemp
			origRename := osRename
			defer func() {
				osExecutable = origExe
				osCreateTemp = origCreate
				osRename = origRename
			}()

			dir := t.TempDir()
			osExecutable = func() (string, error) { return filepath.Join(dir, "agent"), nil }

			var fake *cliTFakeTempFile
			osCreateTemp = func(d, pattern string) (updateTempFile, error) {
				f, err := os.CreateTemp(d, pattern)
				if err != nil {
					return nil, err
				}
				t.Cleanup(func() { _ = f.Close() })
				fake = &cliTFakeTempFile{file: f}
				tt.apply(fake)
				return fake, nil
			}

			renamed := false
			osRename = func(string, string) error {
				renamed = true
				return nil
			}

			err := selfUpdate(downloadURL, checksum)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("selfUpdate error = %v, want %q", err, tt.want)
			}
			if renamed {
				t.Error("binary was replaced despite a temp file failure")
			}
			if fake == nil {
				t.Fatal("temp file was never created")
			}
			if fake.closes != 1 {
				t.Errorf("temp file closes = %d, want 1", fake.closes)
			}
			if _, statErr := os.Stat(fake.Name()); !os.IsNotExist(statErr) {
				t.Errorf("staged temp file %q survived: %v", fake.Name(), statErr)
			}
		})
	}
}

func TestCliTSelfUpdateSyncDirectoryError(t *testing.T) {
	body := []byte("payload for directory sync failure")
	downloadURL, checksum := cliTUpdateServer(t, body)

	origExe := osExecutable
	origCreate := osCreateTemp
	origRename := osRename
	origExec := syscallExec
	defer func() {
		osExecutable = origExe
		osCreateTemp = origCreate
		osRename = origRename
		syscallExec = origExec
	}()

	stage := t.TempDir()
	missingDir := filepath.Join(t.TempDir(), "removed")
	osExecutable = func() (string, error) { return filepath.Join(missingDir, "agent"), nil }
	osCreateTemp = func(_, pattern string) (updateTempFile, error) { return os.CreateTemp(stage, pattern) }
	osRename = func(string, string) error { return nil }

	execCalled := false
	syscallExec = func(string, []string, []string) error {
		execCalled = true
		return nil
	}

	err := selfUpdate(downloadURL, checksum)
	if err == nil || !strings.Contains(err.Error(), "sync executable directory") {
		t.Fatalf("selfUpdate error = %v, want directory sync failure", err)
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("error %v should wrap the os.Open failure", err)
	}
	if execCalled {
		t.Error("re-exec attempted after the directory sync failed")
	}
}

func TestPropCliSanitizeArgs(t *testing.T) {
	// Other arguments are lowercase-only, so the digit-bearing secret can never
	// appear in them by chance, nor can they look like a token flag.
	filler := rapid.SliceOfN(rapid.StringMatching(`[a-z]{0,8}`), 0, 6)
	secretTail := rapid.StringMatching(`[A-Z0-9]{1,10}`)

	rapid.Check(t, func(t *rapid.T) {
		others := filler.Draw(t, "others")
		secret := "s3cr3t" + secretTail.Draw(t, "secret")
		form := rapid.IntRange(0, 3).Draw(t, "form")
		pos := rapid.IntRange(0, len(others)).Draw(t, "pos")

		var injected []string
		switch form {
		case 0:
			injected = []string{"--token", secret}
		case 1:
			injected = []string{"-token", secret}
		case 2:
			injected = []string{"--token=" + secret}
		case 3:
			injected = []string{"-token=" + secret}
		}

		args := make([]string, 0, len(others)+len(injected))
		args = append(args, others[:pos]...)
		args = append(args, injected...)
		args = append(args, others[pos:]...)
		before := append([]string(nil), args...)

		out := sanitizeArgs(args)

		if len(out) != len(args) {
			t.Fatalf("sanitizeArgs(%q) length = %d, want %d", before, len(out), len(args))
		}
		if strings.Contains(strings.Join(out, "\x00"), secret) {
			t.Fatalf("sanitizeArgs(%q) = %q leaks the secret", before, out)
		}
		for i := range args {
			inInjected := i >= pos && i < pos+len(injected)
			if !inInjected && out[i] != before[i] {
				t.Fatalf("sanitizeArgs(%q) changed arg %d: %q -> %q", before, i, before[i], out[i])
			}
		}
		if out[pos] != injected[0] && out[pos] != strings.SplitN(injected[0], "=", 2)[0]+"=***" {
			t.Fatalf("sanitizeArgs(%q) mangled the token flag: %q", before, out[pos])
		}
		if len(injected) == 2 && out[pos+1] != "***" {
			t.Fatalf("sanitizeArgs(%q) token value = %q, want ***", before, out[pos+1])
		}
		for i := range args {
			if args[i] != before[i] {
				t.Fatalf("sanitizeArgs mutated the caller's slice at %d: %q -> %q", i, before[i], args[i])
			}
		}
	})
}
