// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// elfUpdateBody returns the smallest download selfUpdateContext's staged-
// binary check accepts on this host: an ELF64 executable header. machine
// sets the ELF architecture field.
func elfUpdateBody(machine elf.Machine) []byte {
	body := make([]byte, 64)
	copy(body, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(body[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(body[18:], uint16(machine))
	binary.LittleEndian.PutUint32(body[20:], 1)
	binary.LittleEndian.PutUint16(body[52:], 64)
	binary.LittleEndian.PutUint16(body[54:], 56)
	binary.LittleEndian.PutUint16(body[58:], 64)
	return body
}

// elfUpdateBodyForHost builds a payload matching this test host's arch, the
// only arch validateStagedBinary accepts.
func elfUpdateBodyForHost() []byte {
	machine, ok := elfMachineForGOARCH(runtime.GOARCH)
	if !ok {
		// A host with no ELF mapping accepts any ELF executable.
		return elfUpdateBody(elf.EM_X86_64)
	}
	return elfUpdateBody(machine)
}

// stageExecutable writes the running binary osExecutable is stubbed to
// point at: the update path now renames it aside, so it must exist.
func stageExecutable(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "test-agent")
	if err := os.WriteFile(exe, []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	return exe
}

func forceBareBinaryUpdate(t *testing.T) {
	t.Helper()
	orig := runningInContainer
	runningInContainer = func() bool { return false }
	t.Cleanup(func() { runningInContainer = orig })
}

type cancelUpdateReader struct {
	reader io.Reader
	cancel func()
}

func (r *cancelUpdateReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.cancel()
	}
	return n, err
}

type cancelUpdateTempFile struct {
	updateTempFile
	cancel func()
}

func (f *cancelUpdateTempFile) Close() error {
	err := f.updateTempFile.Close()
	f.cancel()
	return err
}

func TestSelfUpdateCancellationBeforeReplacement(t *testing.T) {
	forceBareBinaryUpdate(t)
	for _, stage := range []string{"download", "staging"} {
		t.Run(stage, func(t *testing.T) {
			origDo, origExe, origCreate, origRename := httpDo, osExecutable, osCreateTemp, osRename
			t.Cleanup(func() {
				httpDo, osExecutable, osCreateTemp, osRename = origDo, origExe, origCreate, origRename
			})
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			cause := errors.New("update request withdrawn")
			cancelUpdate := func() { cancel(cause) }
			body := "replacement binary"
			httpDo = func(req *http.Request) (*http.Response, error) {
				var reader io.Reader = strings.NewReader(body)
				if stage == "download" {
					reader = &cancelUpdateReader{reader: reader, cancel: cancelUpdate}
				}
				return &http.Response{StatusCode: http.StatusOK, Request: req, Body: io.NopCloser(reader)}, nil
			}
			dir := t.TempDir()
			exe := filepath.Join(dir, "agent")
			if err := os.WriteFile(exe, []byte("original binary"), 0700); err != nil {
				t.Fatal(err)
			}
			osExecutable = func() (string, error) { return exe, nil }
			osCreateTemp = func(dir, pattern string) (updateTempFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				if stage == "staging" {
					return &cancelUpdateTempFile{updateTempFile: file, cancel: cancelUpdate}, nil
				}
				return file, nil
			}
			renamed := false
			osRename = func(string, string) error {
				renamed = true
				return errors.New("unexpected replacement")
			}
			err := selfUpdateContext(ctx, "https://example.com/agent", fmt.Sprintf("%x", sha256.Sum256([]byte(body))), "1.2.3")
			if !errors.Is(err, cause) || renamed {
				t.Fatalf("update error = %v, renamed = %v; want cancellation cause before replacement", err, renamed)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "agent" {
				t.Fatalf("staged update not cleaned up: %v", entries)
			}
		})
	}
}

func TestDetectContainer(t *testing.T) {
	origMarkers := containerMarkerFiles
	origCgroup := containerCgroupPath
	origCgroupNamespace := containerCgroupNamespacePath
	origMountInfo := containerMountInfoPath
	t.Cleanup(func() {
		containerMarkerFiles = origMarkers
		containerCgroupPath = origCgroup
		containerCgroupNamespacePath = origCgroupNamespace
		containerMountInfoPath = origMountInfo
	})

	tests := []struct {
		name            string
		markerIndex     int
		cgroup          string
		cgroupNamespace string
		mountInfo       string
		want            bool
	}{
		{name: "docker marker", markerIndex: 0, want: true},
		{name: "podman marker", markerIndex: 1, want: true},
		{name: "kubernetes cgroup", markerIndex: -1, cgroup: "0::/kubepods.slice/pod123", want: true},
		{
			name:            "cgroup v2 root in private namespace",
			markerIndex:     -1,
			cgroup:          "0::/\n",
			cgroupNamespace: "cgroup:[4026533000]",
			mountInfo:       "21 1 8:1 / / rw - ext4 /dev/root rw",
			want:            true,
		},
		{
			name:            "cgroup v2 root in initial namespace",
			markerIndex:     -1,
			cgroup:          "0::/\n",
			cgroupNamespace: initialCgroupNamespace,
			mountInfo:       "21 1 8:1 / / rw - ext4 /dev/root rw",
			want:            false,
		},
		{
			name:        "cgroup v2 root with unreadable namespace",
			markerIndex: -1,
			cgroup:      "0::/\n",
			mountInfo:   "21 1 8:1 / / rw - ext4 /dev/root rw",
			want:        false,
		},
		{
			name:        "overlay root mount",
			markerIndex: -1,
			mountInfo:   "33 21 0:32 / / rw,relatime - overlay overlay rw,lowerdir=/overlay/ro",
			want:        true,
		},
		{
			name:        "overlayfs root mount",
			markerIndex: -1,
			mountInfo:   "33 21 0:32 / / rw,relatime - overlayfs overlay rw,lowerdir=/overlay/ro",
			want:        true,
		},
		{
			name:        "host docker data mount",
			markerIndex: -1,
			cgroup:      "0::/init.scope",
			mountInfo:   "21 1 0:20 /docker/overlay2/rootfs /var/lib/docker rw - ext4 /dev/root rw",
		},
		{name: "no container evidence", markerIndex: -1, cgroup: "0::/init.scope", mountInfo: "21 1 8:1 / / rw - ext4 /dev/root rw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			containerMarkerFiles = []string{
				filepath.Join(dir, ".dockerenv"),
				filepath.Join(dir, ".containerenv"),
			}
			containerCgroupPath = filepath.Join(dir, "cgroup")
			containerCgroupNamespacePath = filepath.Join(dir, "cgroup-namespace")
			containerMountInfoPath = filepath.Join(dir, "mountinfo")

			if tt.markerIndex >= 0 {
				if err := os.WriteFile(containerMarkerFiles[tt.markerIndex], nil, 0600); err != nil {
					t.Fatalf("create container marker: %v", err)
				}
			}
			if tt.cgroup != "" {
				if err := os.WriteFile(containerCgroupPath, []byte(tt.cgroup), 0600); err != nil {
					t.Fatalf("write cgroup fixture: %v", err)
				}
			}
			if tt.cgroupNamespace != "" {
				if err := os.Symlink(tt.cgroupNamespace, containerCgroupNamespacePath); err != nil {
					t.Fatalf("create cgroup namespace fixture: %v", err)
				}
			}
			if tt.mountInfo != "" {
				if err := os.WriteFile(containerMountInfoPath, []byte(tt.mountInfo), 0600); err != nil {
					t.Fatalf("write mountinfo fixture: %v", err)
				}
			}

			if got := detectContainer(); got != tt.want {
				t.Errorf("detectContainer() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSelfUpdateRejectsContainerBeforeDownload(t *testing.T) {
	origContainer := runningInContainer
	origDo := httpDo
	origCreate := osCreateTemp
	t.Cleanup(func() {
		runningInContainer = origContainer
		httpDo = origDo
		osCreateTemp = origCreate
	})

	runningInContainer = func() bool { return true }
	httpCalled := false
	httpDo = func(*http.Request) (*http.Response, error) {
		httpCalled = true
		return nil, errors.New("unexpected download")
	}
	createTempCalled := false
	osCreateTemp = func(string, string) (updateTempFile, error) {
		createTempCalled = true
		return nil, errors.New("unexpected temp file")
	}

	const want = "self-update unsupported in this deployment: the agent runs in a container image; update by pulling a new image"
	err := selfUpdateContext(context.Background(), "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if err == nil || err.Error() != want {
		t.Fatalf("selfUpdate error = %v, want %q", err, want)
	}
	if httpCalled {
		t.Error("httpDo called for a container self-update")
	}
	if createTempCalled {
		t.Error("osCreateTemp called for a container self-update")
	}
}

func TestSelfUpdateRejectsMalformedChecksumBeforeDownload(t *testing.T) {
	forceBareBinaryUpdate(t)
	origDo := httpDo
	t.Cleanup(func() { httpDo = origDo })

	httpCalled := false
	httpDo = func(*http.Request) (*http.Response, error) {
		httpCalled = true
		return nil, errors.New("unexpected download")
	}

	err := selfUpdateContext(context.Background(), "https://example.com/agent", "not-a-checksum", "1.2.3")
	if err == nil || err.Error() != "checksum must be exactly 64 hexadecimal characters" {
		t.Fatalf("selfUpdate error = %v, want malformed checksum rejection", err)
	}
	if httpCalled {
		t.Error("httpDo called for a malformed checksum")
	}
}

func TestSelfUpdateRejectsHTTP(t *testing.T) {
	forceBareBinaryUpdate(t)
	err := selfUpdateContext(context.Background(), "http://example.com/agent", "abc123", "1.2.3")
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("expected 'HTTPS required' in error, got: %v", err)
	}
}

func TestSelfUpdateRejectsRedirectToHTTP(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "after redirects") {
		t.Fatalf("selfUpdate error = %v, want HTTPS redirect rejection", err)
	}
}

func TestSelfUpdateRequiresChecksum(t *testing.T) {
	forceBareBinaryUpdate(t)
	err := selfUpdateContext(context.Background(), "https://example.com/agent", "", "1.2.3")
	if err == nil {
		t.Error("expected error for empty checksum")
	}
	if !strings.Contains(err.Error(), "checksum required") {
		t.Errorf("expected 'checksum required' in error, got: %v", err)
	}
}

func TestSelfUpdateBadURL(t *testing.T) {
	forceBareBinaryUpdate(t)
	err := selfUpdateContext(context.Background(), "https://127.0.0.1:1/nonexistent", strings.Repeat("0", 64), "1.2.3")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestSelfUpdateChecksumMismatch(t *testing.T) {
	forceBareBinaryUpdate(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fake binary"))
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), "0000000000000000000000000000000000000000000000000000000000000000", "1.2.3")
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestSelfUpdate404(t *testing.T) {
	forceBareBinaryUpdate(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL)+"/missing", strings.Repeat("0", 64), "1.2.3")
	if err == nil {
		t.Error("expected error for 404 response")
	}
	if err != nil && !strings.Contains(err.Error(), "status 404") {
		t.Errorf("expected 'status 404' in error, got: %v", err)
	}
}

func TestSelfUpdateReadBodyError(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), strings.Repeat("0", 64), "1.2.3")
	// This may or may not error depending on io.ReadAll behavior with truncated body
	// but we exercise the code path
	_ = err
}

func TestSelfUpdateOsExecutableError(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
	if err == nil {
		t.Error("expected os.Executable error")
	}
	if !strings.Contains(err.Error(), "get executable path") {
		t.Errorf("expected 'get executable path' in error, got: %v", err)
	}
}

func TestSelfUpdateCreateTempError(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
	if err == nil {
		t.Error("expected create temp error")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Errorf("expected 'create temp' in error, got: %v", err)
	}
}

func TestSelfUpdateRenameError(t *testing.T) {
	forceBareBinaryUpdate(t)
	origExe := osExecutable
	origRename := osRename
	defer func() {
		osExecutable = origExe
		osRename = origRename
	}()
	dir := t.TempDir()
	osExecutable = func() (string, error) { return filepath.Join(dir, "test-agent"), nil }
	// The backup is a hard link now; failing it must stop before anything
	// at the executable path is touched.
	origLink := osLink
	defer func() { osLink = origLink }()
	osLink = func(oldpath, newpath string) error {
		return fmt.Errorf("permission denied")
	}
	osRename = func(oldpath, newpath string) error {
		return fmt.Errorf("permission denied")
	}

	body := elfUpdateBodyForHost()
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
	if err == nil {
		t.Error("expected rename error")
	}
	// The first step is linking the running binary aside; a failure there
	// surfaces through it now.
	if !strings.Contains(err.Error(), "backup current binary") {
		t.Errorf("expected 'backup current binary' in error, got: %v", err)
	}
}

func TestSelfUpdateChecksumMatch(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
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
	// os.Executable/os.Link/os.Rename/syscall.Exec run would overwrite and
	// re-exec the test binary itself. The exe must exist because the backup
	// links the running binary before the stubbed rename.
	dir := t.TempDir()
	exePath := filepath.Join(dir, "test-agent")
	if err := os.WriteFile(exePath, []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = func(string, string) error { return fmt.Errorf("stop before replacing binary") }

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
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
	forceBareBinaryUpdate(t)
	origExe := osExecutable
	origRename := osRename
	defer func() {
		osExecutable = origExe
		osRename = origRename
	}()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }

	// The staged file is what the chmod lands on: it is the rename's source
	// (the backup is a hard link now). It is deleted by cleanup on return,
	// so capture its mode from inside the stub.
	var capturedPerm os.FileMode
	renames := 0
	osRename = func(oldpath, newpath string) error {
		renames++
		if renames == 1 {
			info, statErr := os.Stat(oldpath)
			if statErr != nil {
				t.Fatalf("staged file missing: %v", statErr)
			}
			capturedPerm = info.Mode().Perm()
			return fmt.Errorf("stop here") // stop before re-exec
		}
		return os.Rename(oldpath, newpath)
	}

	body := elfUpdateBodyForHost()
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	_ = selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")

	if renames < 1 {
		t.Fatalf("expected the staged binary rename, got %d rename calls", renames)
	}
	if capturedPerm != 0700 {
		t.Errorf("expected file permissions 0700, got %o", capturedPerm)
	}
}

func TestSelfUpdateTooLarge(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
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
		{"trap community separate value", []string{"agent", "--trap-community", "public"}, []string{"agent", "--trap-community", "***"}},
		{"trap community equals", []string{"agent", "--trap-community=public"}, []string{"agent", "--trap-community=***"}},
		{"trap community trailing no value", []string{"agent", "--trap-community"}, []string{"agent", "--trap-community"}},
		{"trap community single dash", []string{"agent", "-trap-community", "public"}, []string{"agent", "-trap-community", "***"}},
		{"token flag prefix does not leak", []string{"agent", "--tokenized=secret"}, []string{"agent", "--tokenized=secret"}},
		{"both secrets masked", []string{"agent", "--token", "a", "--trap-community", "b"}, []string{"agent", "--token", "***", "--trap-community", "***"}},
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
	forceBareBinaryUpdate(t)
	err := selfUpdateContext(context.Background(), "://\x7f", "abc123", "1.2.3")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
	if err != nil && !strings.Contains(err.Error(), "parse url") {
		t.Errorf("expected 'parse url' in error, got: %v", err)
	}
}

func TestSelfUpdateFullHappyPath(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
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

	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = func(oldpath, newpath string) error {
		return os.Rename(oldpath, newpath) // real rename within temp dir
	}
	syscallExec = func(argv0 string, argv []string, envv []string) error {
		return nil // success - don't actually re-exec
	}

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
	if err != nil {
		t.Errorf("expected nil error on full happy path, got: %v", err)
	}
}

func TestSelfUpdateDrainsSpoolBeforeExec(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
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
		drainResultSpool.Store(nil)
	}()
	httpDo = srv.Client().Do

	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = os.Rename

	var drainCalled, execCalled bool
	var sawDeadline bool
	drain := func(ctx context.Context) bool {
		drainCalled = true
		deadline, ok := ctx.Deadline()
		sawDeadline = ok && time.Until(deadline) <= spoolDrainTimeout
		return true
	}
	drainResultSpool.Store(&drain)
	syscallExec = func(argv0 string, argv []string, envv []string) error {
		execCalled = true
		if !drainCalled {
			t.Error("re-exec ran before the spool drain")
		}
		return nil
	}

	if err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3"); err != nil {
		t.Fatalf("selfUpdateContext: %v", err)
	}
	if !drainCalled {
		t.Error("drain hook never ran")
	}
	if !sawDeadline {
		t.Error("drain hook context had no bounded deadline")
	}
	if !execCalled {
		t.Error("re-exec never ran")
	}
}

func TestSelfUpdateExecsWhenDrainStalls(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origDo := httpDo
	origExe := osExecutable
	origRename := osRename
	origExec := syscallExec
	origTimeout := spoolDrainTimeout
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		osRename = origRename
		syscallExec = origExec
		spoolDrainTimeout = origTimeout
		drainResultSpool.Store(nil)
	}()
	httpDo = srv.Client().Do
	spoolDrainTimeout = 20 * time.Millisecond

	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = os.Rename

	drain := func(ctx context.Context) bool {
		<-ctx.Done()
		return false
	}
	drainResultSpool.Store(&drain)

	var execCalled bool
	syscallExec = func(argv0 string, argv []string, envv []string) error {
		execCalled = true
		return nil
	}

	if err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3"); err != nil {
		t.Fatalf("selfUpdateContext: %v", err)
	}
	if !execCalled {
		t.Error("re-exec never ran after the drain timed out")
	}
}

func TestSelfUpdateWriteError(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), checksum, "1.2.3")
	if err == nil {
		t.Error("expected write error")
	}
}

func TestSelfUpdateResponseHeaderTimeout(t *testing.T) {
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
}

// tpTTrackingBody records that the caller closed the response body.
type tpTTrackingBody struct {
	io.Reader
	closed chan struct{}
}

func (b *tpTTrackingBody) Close() error {
	close(b.closed)
	return nil
}

func TestSelfUpdateHeaderTimeoutClosesLateResponseBody(t *testing.T) {
	forceBareBinaryUpdate(t)
	origDo := httpDo
	origTimeout := selfUpdateTimeout
	origCreate := osCreateTemp
	t.Cleanup(func() {
		httpDo = origDo
		selfUpdateTimeout = origTimeout
		osCreateTemp = origCreate
	})

	body := &tpTTrackingBody{Reader: strings.NewReader("late payload"), closed: make(chan struct{})}
	httpDo = func(req *http.Request) (*http.Response, error) {
		// Return only after the header watchdog has already fired, so the
		// response arrives too late to be used but still owns a live body.
		<-req.Context().Done()
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}
	selfUpdateTimeout = 10 * time.Millisecond
	osCreateTemp = func(string, string) (updateTempFile, error) {
		t.Error("osCreateTemp called after the header timeout")
		return nil, errors.New("unexpected temp file")
	}

	err := selfUpdateContext(context.Background(), "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-body.closed:
	default:
		t.Error("late response body was not closed")
	}
}

func TestSelfUpdateDownloadErrorReportsCancellationCause(t *testing.T) {
	forceBareBinaryUpdate(t)
	origDo := httpDo
	origCreate := osCreateTemp
	t.Cleanup(func() {
		httpDo = origDo
		osCreateTemp = origCreate
	})

	cause := errors.New("caller shut down the agent")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)

	transportErr := errors.New("transport gave up")
	httpDo = func(*http.Request) (*http.Response, error) { return nil, transportErr }
	osCreateTemp = func(string, string) (updateTempFile, error) {
		t.Error("osCreateTemp called after a failed download")
		return nil, errors.New("unexpected temp file")
	}

	err := selfUpdateContext(ctx, "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if !errors.Is(err, cause) {
		t.Fatalf("got %v, want cancellation cause %v", err, cause)
	}
	if errors.Is(err, transportErr) {
		t.Errorf("got %v, want the cancellation cause instead of the transport error", err)
	}
}

func TestSelfUpdateSlowProgressingDownloadCompletes(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	origDo := httpDo
	origExe := osExecutable
	origRename := osRename
	origExec := syscallExec
	origTimeout := selfUpdateTimeout
	origIdleTimeout := selfUpdateIdleTimeout
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		osRename = origRename
		syscallExec = origExec
		selfUpdateTimeout = origTimeout
		selfUpdateIdleTimeout = origIdleTimeout
	}()

	httpDo = func(req *http.Request) (*http.Response, error) {
		reader, writer := io.Pipe()
		go func() {
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			defer func() { _ = writer.Close() }()

			for offset := 0; offset < len(body); offset += 4 {
				select {
				case <-ticker.C:
					select {
					case <-req.Context().Done():
						_ = writer.CloseWithError(req.Context().Err())
						return
					default:
					}
					end := min(offset+4, len(body))
					if _, err := writer.Write(body[offset:end]); err != nil {
						return
					}
				case <-req.Context().Done():
					_ = writer.CloseWithError(req.Context().Err())
					return
				}
			}
		}()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       reader,
			Request:    req,
		}, nil
	}
	selfUpdateTimeout = 50 * time.Millisecond
	selfUpdateIdleTimeout = 500 * time.Millisecond

	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = os.Rename
	syscallExec = func(string, []string, []string) error { return nil }

	if err := selfUpdateContext(context.Background(), "https://example.com/agent", checksum, "1.2.3"); err != nil {
		t.Fatalf("slow progressing update failed: %v", err)
	}
}

func TestSelfUpdateStalledBodyTimesOut(t *testing.T) {
	forceBareBinaryUpdate(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	origDo := httpDo
	origExe := osExecutable
	origTimeout := selfUpdateTimeout
	origIdleTimeout := selfUpdateIdleTimeout
	defer func() {
		httpDo = origDo
		osExecutable = origExe
		selfUpdateTimeout = origTimeout
		selfUpdateIdleTimeout = origIdleTimeout
	}()

	httpDo = srv.Client().Do
	osExecutable = func() (string, error) { return filepath.Join(t.TempDir(), "test-agent"), nil }
	selfUpdateTimeout = 500 * time.Millisecond
	selfUpdateIdleTimeout = 25 * time.Millisecond

	err := selfUpdateContext(context.Background(), rewriteToHTTPS(srv.URL), strings.Repeat("0", 64), "1.2.3")
	if err == nil {
		t.Fatal("expected stalled download body to time out")
	}
	if !strings.Contains(err.Error(), "idle timeout") {
		t.Fatalf("stalled download error = %v, want idle timeout", err)
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
	forceBareBinaryUpdate(t)
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

	err := selfUpdateContext(context.Background(), "https://example.com/agent", strings.Repeat("0", 64), "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "build request: unsupported protocol scheme") {
		t.Fatalf("selfUpdate error = %v, want build request failure", err)
	}
}

func TestCliTSelfUpdateTempFileFailures(t *testing.T) {
	forceBareBinaryUpdate(t)
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

			err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
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
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
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
	// The backup link is faked like the renames: neither the exe nor its
	// directory exists in this scenario.
	origLink := osLink
	defer func() { osLink = origLink }()
	osLink = func(string, string) error { return nil }

	execCalled := false
	syscallExec = func(string, []string, []string) error {
		execCalled = true
		return nil
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
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
	t.Parallel()

	// Other arguments are lowercase-only, so the digit-bearing secret can never
	// appear in them by chance, nor can they look like a token flag.
	filler := rapid.SliceOfN(rapid.StringMatching(`[a-z]{0,8}`), 0, 6)
	secretTail := rapid.StringMatching(`[A-Z0-9]{1,10}`)

	rapid.Check(t, func(t *rapid.T) {
		others := filler.Draw(t, "others")
		secret := "s3cr3t" + secretTail.Draw(t, "secret")
		flag := rapid.SampledFrom([]string{"token", "trap-community"}).Draw(t, "flag")
		form := rapid.IntRange(0, 3).Draw(t, "form")
		pos := rapid.IntRange(0, len(others)).Draw(t, "pos")

		var injected []string
		switch form {
		case 0:
			injected = []string{"--" + flag, secret}
		case 1:
			injected = []string{"-" + flag, secret}
		case 2:
			injected = []string{"--" + flag + "=" + secret}
		case 3:
			injected = []string{"-" + flag + "=" + secret}
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
			t.Fatalf("sanitizeArgs(%q) mangled the secret flag: %q", before, out[pos])
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

// updateTestServer serves body over TLS and returns the server, download
// URL and matching checksum.
func updateTestServer(t *testing.T, body []byte) (*httptest.Server, string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, rewriteToHTTPS(srv.URL), fmt.Sprintf("%x", sha256.Sum256(body))
}

// stubUpdateIO replaces the filesystem/HTTP/exec seams the update path
// touches and restores them on cleanup.
func stubUpdateIO(t *testing.T, srv *httptest.Server, exePath string) {
	t.Helper()
	origDo, origExe, origRename, origExec := httpDo, osExecutable, osRename, syscallExec
	t.Cleanup(func() {
		httpDo, osExecutable, osRename, syscallExec = origDo, origExe, origRename, origExec
	})
	httpDo = srv.Client().Do
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = os.Rename
	syscallExec = func(string, []string, []string) error { return nil }
}

func TestSelfUpdateRejectsNonExecutable(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := []byte("this is plainly not an ELF binary")
	srv, downloadURL, checksum := updateTestServer(t, body)

	exePath := stageExecutable(t)
	origExe, origRename := osExecutable, osRename
	defer func() { osExecutable, osRename = origExe, origRename }()
	osExecutable = func() (string, error) { return exePath, nil }
	origDo := httpDo
	defer func() { httpDo = origDo }()
	httpDo = srv.Client().Do

	renamed := false
	osRename = func(string, string) error {
		renamed = true
		return nil
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "not an executable binary") {
		t.Fatalf("selfUpdate error = %v, want staged-binary rejection", err)
	}
	if renamed {
		t.Error("running binary was touched for a payload that cannot execute")
	}
}

func TestSelfUpdateRejectsWrongArch(t *testing.T) {
	forceBareBinaryUpdate(t)
	host, ok := elfMachineForGOARCH(runtime.GOARCH)
	if !ok {
		t.Skip("test host has no ELF mapping; wrong-arch cannot be constructed")
	}
	wrong := elf.EM_X86_64
	if host == elf.EM_X86_64 {
		wrong = elf.EM_AARCH64
	}
	body := elfUpdateBody(wrong)
	srv, downloadURL, checksum := updateTestServer(t, body)

	exePath := stageExecutable(t)
	origDo, origExe, origRename := httpDo, osExecutable, osRename
	defer func() { httpDo, osExecutable, osRename = origDo, origExe, origRename }()
	httpDo = srv.Client().Do
	osExecutable = func() (string, error) { return exePath, nil }

	renamed := false
	osRename = func(string, string) error {
		renamed = true
		return nil
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "this agent runs") {
		t.Fatalf("selfUpdate error = %v, want wrong-arch rejection", err)
	}
	if renamed {
		t.Error("running binary was touched for a wrong-arch payload")
	}
	// The rejection must leave the running binary's bytes alone.
	content, _ := os.ReadFile(exePath)
	if string(content) != "previous binary" {
		t.Errorf("running binary was modified: %q", content)
	}
}

func TestSelfUpdateExecFailureRestoresPrev(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)

	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	syscallExec = func(string, []string, []string) error {
		return errors.New("exec format error")
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "re-exec updated binary") {
		t.Fatalf("selfUpdate error = %v, want re-exec failure", err)
	}
	content, readErr := os.ReadFile(exePath)
	if readErr != nil || string(content) != "previous binary" {
		t.Errorf("previous binary not restored: content %q, err %v", content, readErr)
	}
	if _, statErr := os.Stat(exePath + ".update-pending"); !os.IsNotExist(statErr) {
		t.Error("update-pending marker survived an exec failure")
	}
}

func TestSelfUpdateHappyPathKeepsPrevAndMarker(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)

	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	if err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3"); err != nil {
		t.Fatalf("selfUpdateContext: %v", err)
	}
	prev, err := os.ReadFile(exePath + ".prev")
	if err != nil || string(prev) != "previous binary" {
		t.Fatalf("backup binary missing or wrong: %q, err %v", prev, err)
	}
	marker, err := os.ReadFile(exePath + ".update-pending")
	if err != nil {
		t.Fatal("update-pending marker missing after replacement")
	}
	if !strings.Contains(string(marker), "1.2.3") {
		t.Errorf("marker does not carry the target version: %s", marker)
	}
}

func TestCheckPendingUpdateArmsWatchdog(t *testing.T) {
	origExe, origTimeout := osExecutable, updateJoinTimeout
	defer func() {
		osExecutable = origExe
		updateJoinTimeout = origTimeout
		if timer := updateWatchdog.Swap(nil); timer != nil {
			timer.Stop()
		}
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}

	p := checkPendingUpdate()
	if p == nil || p.Attempts != 1 {
		t.Fatalf("checkPendingUpdate = %+v, want one recorded attempt", p)
	}
	if armedUpdate.Load() == nil || updateWatchdog.Load() == nil {
		t.Fatal("watchdog was not armed for the pending update")
	}
	// The attempt counter must persist for the crash-loop bound.
	data, _ := os.ReadFile(exePath + ".update-pending")
	var stored pendingUpdate
	if err := json.Unmarshal(data, &stored); err != nil || stored.Attempts != 1 {
		t.Fatalf("marker attempts = %+v, err %v; want 1", stored, err)
	}
}

func TestWatchdogRollbackRestoresPrev(t *testing.T) {
	origExe, origTimeout := osExecutable, updateJoinTimeout
	defer func() {
		osExecutable = origExe
		updateJoinTimeout = origTimeout
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	// The unproven build sits at the exe path; its predecessor is the backup.
	if err := os.WriteFile(exePath, []byte("unproven binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".prev", []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }

	exited := make(chan int, 1)
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) { exited <- code }
	updateJoinTimeout = 10 * time.Millisecond

	_ = checkPendingUpdate()
	select {
	case code := <-exited:
		if code != 1 {
			t.Errorf("osExit code = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never fired")
	}
	content, err := os.ReadFile(exePath)
	if err != nil || string(content) != "previous binary" {
		t.Errorf("rollback did not restore previous binary: %q, err %v", content, err)
	}
	if _, err := os.Stat(exePath + ".update-pending"); !os.IsNotExist(err) {
		t.Error("update-pending marker survived the rollback")
	}
	res := readUpdateResult()
	if res == nil || res.Error == "" || res.TargetVersion != "1.2.3" {
		t.Errorf("failure not recorded for the heartbeat: %+v", res)
	}
}

func TestCheckPendingUpdateCrashLoopRollsBack(t *testing.T) {
	origExe := osExecutable
	defer func() {
		osExecutable = origExe
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	if err := os.WriteFile(exePath, []byte("unproven binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".prev", []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		exePath+".update-pending",
		mustJSON(pendingUpdate{Version: "1.2.3", Attempts: maxUpdateBootAttempts}),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }

	exited := make(chan int, 1)
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) { exited <- code }

	_ = checkPendingUpdate()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("crash-loop bound did not exit")
	}
	content, err := os.ReadFile(exePath)
	if err != nil || string(content) != "previous binary" {
		t.Errorf("crash-loop rollback did not restore previous binary: %q, err %v", content, err)
	}
}

func TestUpdateJoinedClearsPending(t *testing.T) {
	origExe := osExecutable
	defer func() {
		osExecutable = origExe
		armedUpdate.Store(nil)
		if timer := updateWatchdog.Swap(nil); timer != nil {
			timer.Stop()
		}
	}()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}

	p := checkPendingUpdate()
	if p == nil {
		t.Fatal("pending update was not armed")
	}
	updateJoined()

	if _, err := os.Stat(exePath + ".update-pending"); !os.IsNotExist(err) {
		t.Error("update-pending marker survived a joined session")
	}
	res := readUpdateResult()
	if res == nil || res.Error != "" || res.TargetVersion != "1.2.3" {
		t.Errorf("success not recorded for the heartbeat: %+v", res)
	}
}

// TestUpdatePathHelpersError covers the executable-resolution failure shared
// by the marker and result path helpers and the readers built on them.
func TestUpdatePathHelpersError(t *testing.T) {
	origExe := osExecutable
	defer func() { osExecutable = origExe }()
	osExecutable = func() (string, error) { return "", errors.New("no executable") }

	if path, err := pendingUpdatePath(); err == nil || path != "" {
		t.Errorf("pendingUpdatePath = %q, %v; want an error", path, err)
	}
	if path, err := updateResultPath(); err == nil || path != "" {
		t.Errorf("updateResultPath = %q, %v; want an error", path, err)
	}
	if res := readUpdateResult(); res != nil {
		t.Errorf("readUpdateResult = %+v without a resolvable path, want nil", res)
	}
	writeUpdateResult(updateResult{TargetVersion: "1.2.3", Error: "boom"}) // must not panic
}

// TestReadUpdateResultMissingAndCorrupt covers the outcome-file states that
// must read as "never attempted" instead of surfacing an error.
func TestReadUpdateResultMissingAndCorrupt(t *testing.T) {
	origExe := osExecutable
	defer func() { osExecutable = origExe }()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }

	if res := readUpdateResult(); res != nil {
		t.Errorf("readUpdateResult on missing file = %+v, want nil", res)
	}
	if err := os.WriteFile(exePath+".update-result", []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if res := readUpdateResult(); res != nil {
		t.Errorf("readUpdateResult on corrupt file = %+v, want nil", res)
	}
}

// TestWriteUpdateResultErrorPaths covers the logged-only failure modes of the
// outcome writer: unresolvable path, encode failure, unwritable path.
func TestWriteUpdateResultErrorPaths(t *testing.T) {
	origExe, origResultPath, origMarshal := osExecutable, updateResultPath, jsonMarshal
	defer func() { osExecutable, updateResultPath, jsonMarshal = origExe, origResultPath, origMarshal }()

	osExecutable = func() (string, error) { return "", errors.New("no executable") }
	writeUpdateResult(updateResult{TargetVersion: "1.2.3", Error: "boom"}) // must not panic

	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("encode failed") }
	writeUpdateResult(updateResult{TargetVersion: "1.2.3"})
	if _, err := os.Stat(exePath + ".update-result"); !os.IsNotExist(err) {
		t.Error("outcome file written despite an encode failure")
	}

	jsonMarshal = json.Marshal
	updateResultPath = func() (string, error) {
		return filepath.Join(exePath, "missing-dir", "agent.update-result"), nil
	}
	writeUpdateResult(updateResult{TargetVersion: "1.2.3"}) // must not panic
}

// TestCheckPendingUpdateUnresolvableExecutable covers the startup guard's
// behavior when the executable path cannot be resolved: stay out of the way.
func TestCheckPendingUpdateUnresolvableExecutable(t *testing.T) {
	origExe := osExecutable
	defer func() { osExecutable = origExe }()
	osExecutable = func() (string, error) { return "", errors.New("no executable") }
	if p := checkPendingUpdate(); p != nil {
		t.Errorf("checkPendingUpdate = %+v, want nil without a resolvable executable", p)
	}
}

// TestCheckPendingUpdateCorruptMarker covers an unreadable marker: it must be
// removed and never arm the watchdog.
func TestCheckPendingUpdateCorruptMarker(t *testing.T) {
	origExe := osExecutable
	defer func() {
		osExecutable = origExe
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	if err := os.WriteFile(exePath+".update-pending", []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	if p := checkPendingUpdate(); p != nil {
		t.Errorf("checkPendingUpdate = %+v, want nil for a corrupt marker", p)
	}
	if _, err := os.Stat(exePath + ".update-pending"); !os.IsNotExist(err) {
		t.Error("corrupt marker was not removed")
	}
	if armedUpdate.Load() != nil {
		t.Error("watchdog armed for a corrupt marker")
	}
}

// TestCheckPendingUpdateArmsWhenMarkerRewriteFails covers a read-only marker:
// the attempt count cannot persist, but the boot must still be guarded.
func TestCheckPendingUpdateArmsWhenMarkerRewriteFails(t *testing.T) {
	origExe := osExecutable
	defer func() {
		osExecutable = origExe
		if timer := updateWatchdog.Swap(nil); timer != nil {
			timer.Stop()
		}
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return exePath, nil }
	marker := exePath + ".update-pending"
	if err := os.WriteFile(marker, mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0400); err != nil {
		t.Fatal(err)
	}

	p := checkPendingUpdate()
	if p == nil || p.Attempts != 1 {
		t.Fatalf("checkPendingUpdate = %+v, want one recorded attempt", p)
	}
	if updateWatchdog.Load() == nil {
		t.Error("watchdog not armed despite the marker rewrite failure")
	}
}

// TestRollbackUpdateWithoutExecutable covers a rollback that cannot resolve
// the executable path: nothing may be touched.
func TestRollbackUpdateWithoutExecutable(t *testing.T) {
	origExe := osExecutable
	defer func() { osExecutable = origExe }()
	exePath := stageExecutable(t)
	osExecutable = func() (string, error) { return "", errors.New("no executable") }
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}

	rollbackUpdate("executable unresolvable")
	if _, err := os.Stat(exePath + ".update-pending"); err != nil {
		t.Errorf("pending marker disturbed by a rollback without an executable: %v", err)
	}
}

// TestRollbackUpdateRestoreFailure covers the rename failure inside a
// rollback: the failure and the failed restore both reach the outcome file.
func TestRollbackUpdateRestoreFailure(t *testing.T) {
	origExe, origRename := osExecutable, osRename
	defer func() {
		osExecutable, osRename = origExe, origRename
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	if err := os.WriteFile(exePath, []byte("unproven binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".prev", []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }
	osRename = func(string, string) error { return errors.New("device busy") }

	rollbackUpdate("watchdog fired")
	res := readUpdateResult()
	if res == nil || res.TargetVersion != "1.2.3" || !strings.Contains(res.Error, "rollback failed") {
		t.Errorf("rollback failure not recorded: %+v", res)
	}
}

// TestRollbackUpdateSyncFailure covers a failed post-restore fsync: the
// restore still stands and the outcome records only the original reason.
func TestRollbackUpdateSyncFailure(t *testing.T) {
	origExe, origSync := osExecutable, syncDirectory
	defer func() {
		osExecutable, syncDirectory = origExe, origSync
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	if err := os.WriteFile(exePath, []byte("unproven binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".prev", []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }
	syncDirectory = func(string) error { return errors.New("sync failed") }

	rollbackUpdate("did not join")
	content, err := os.ReadFile(exePath)
	if err != nil || string(content) != "previous binary" {
		t.Errorf("fsync failure disturbed the restore: %q, err %v", content, err)
	}
	res := readUpdateResult()
	if res == nil || res.Error != "did not join" {
		t.Errorf("outcome = %+v, want the original reason only", res)
	}
}

// TestValidateStagedBinaryRejectsNonExecutableELF covers a well-formed ELF
// whose type is neither executable nor shared object (e.g. a relocatable).
func TestValidateStagedBinaryRejectsNonExecutableELF(t *testing.T) {
	body := elfUpdateBodyForHost()
	binary.LittleEndian.PutUint16(body[16:], uint16(elf.ET_REL))
	path := filepath.Join(t.TempDir(), "staged")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}

	err := validateStagedBinary(path, runtime.GOARCH)
	if err == nil || !strings.Contains(err.Error(), "not an executable binary") {
		t.Fatalf("validateStagedBinary = %v, want an ELF-type rejection", err)
	}
}

// TestValidateStagedBinaryArchetable covers the GOARCH to ELF machine table,
// the unmapped-GOARCH acceptance, and a machine mismatch.
func TestValidateStagedBinaryArchetable(t *testing.T) {
	for _, tc := range []struct {
		goarch  string
		machine elf.Machine
		mapped  bool
	}{
		{"amd64", elf.EM_X86_64, true},
		{"386", elf.EM_386, true},
		{"arm64", elf.EM_AARCH64, true},
		{"arm", elf.EM_ARM, true},
		{"riscv64", elf.EM_RISCV, true},
		{"s390x", elf.EM_NONE, false},
	} {
		machine, mapped := elfMachineForGOARCH(tc.goarch)
		if machine != tc.machine || mapped != tc.mapped {
			t.Errorf("elfMachineForGOARCH(%q) = %s, %v; want %s, %v", tc.goarch, machine, mapped, tc.machine, tc.mapped)
		}
	}

	path := filepath.Join(t.TempDir(), "staged")
	if err := os.WriteFile(path, elfUpdateBody(elf.EM_X86_64), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateStagedBinary(path, "s390x"); err != nil {
		t.Errorf("validateStagedBinary with an unmapped GOARCH = %v, want nil", err)
	}
	err := validateStagedBinary(path, "arm64")
	if err == nil || !strings.Contains(err.Error(), "this agent runs") {
		t.Fatalf("validateStagedBinary = %v, want a machine mismatch", err)
	}
}

// TestMustJSONUnmarshalable covers the defensive nil return for values the
// encoding package rejects.
func TestMustJSONUnmarshalable(t *testing.T) {
	if got := mustJSON(make(chan int)); got != nil {
		t.Errorf("mustJSON = %v, want nil for an unmarshalable value", got)
	}
}

// TestSelfUpdateMarkerPathFallback covers the marker-path helper failing
// mid-update: the marker must still land beside the executable.
func TestSelfUpdateMarkerPathFallback(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	origPending := pendingUpdatePath
	defer func() { pendingUpdatePath = origPending }()
	pendingUpdatePath = func() (string, error) { return "", errors.New("no marker path") }

	if err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3"); err != nil {
		t.Fatalf("selfUpdateContext: %v", err)
	}
	marker, err := os.ReadFile(exePath + ".update-pending")
	if err != nil || !strings.Contains(string(marker), "1.2.3") {
		t.Errorf("marker missing from the fallback path: %q, err %v", marker, err)
	}
}

// TestSelfUpdateStagedRenameFailureKeepsRunningBuild covers the staged build
// failing to land: the hard link keeps the running binary at the executable
// path through the whole swap, and the backup link is cleaned up.
func TestSelfUpdateStagedRenameFailureKeepsRunningBuild(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	osRename = func(oldpath, newpath string) error {
		return errors.New("device busy")
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "rename new binary") {
		t.Fatalf("selfUpdate error = %v, want a staged rename failure", err)
	}
	// The rename failed, so the running build is still untouched at the exe
	// path — nothing for the operator to restore by hand.
	content, readErr := os.ReadFile(exePath)
	if readErr != nil || string(content) != "previous binary" {
		t.Errorf("running binary not intact at the exe path: %q, err %v", content, readErr)
	}
	if _, statErr := os.Stat(exePath + ".prev"); !os.IsNotExist(statErr) {
		t.Errorf("backup link survived the failed staged rename: %v", statErr)
	}
}

// TestSelfUpdateExecFailureRestoreFailure covers a re-exec failure whose
// restore rename also fails: the error surfaces and the marker is dropped so
// the next boot is not treated as unproven.
func TestSelfUpdateExecFailureRestoreFailure(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	calls := 0
	osRename = func(oldpath, newpath string) error {
		calls++
		if calls == 2 { // staged replacement, then the failed restore
			return errors.New("device busy")
		}
		return os.Rename(oldpath, newpath)
	}
	syscallExec = func(string, []string, []string) error {
		return errors.New("exec format error")
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "re-exec updated binary") {
		t.Fatalf("selfUpdate error = %v, want a re-exec failure", err)
	}
	content, readErr := os.ReadFile(exePath)
	if readErr != nil || string(content) != string(body) {
		t.Errorf("staged binary not in place after the failed restore: err %v", readErr)
	}
	if _, statErr := os.Stat(exePath + ".update-pending"); !os.IsNotExist(statErr) {
		t.Error("update-pending marker survived an exec failure with a failed restore")
	}
}

// TestSelfUpdateSyncFailureRestoresPrev pins the directory-sync failure
// path: the staged build is installed by then, so the previous build must
// go back and the marker must go, exactly like an exec failure — a retry
// must not move the unproven build to .prev.
func TestSelfUpdateSyncFailureRestoresPrev(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	origSync := syncDirectory
	t.Cleanup(func() { syncDirectory = origSync })
	syncDirectory = func(string) error { return errors.New("dirsync failed") }

	execCalled := false
	syscallExec = func(string, []string, []string) error {
		execCalled = true
		return nil
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "sync executable directory") {
		t.Fatalf("selfUpdate error = %v, want directory sync failure", err)
	}
	if execCalled {
		t.Error("re-exec attempted although the directory sync failed")
	}
	content, readErr := os.ReadFile(exePath)
	if readErr != nil || string(content) != "previous binary" {
		t.Errorf("previous binary not restored after sync failure: content %q, err %v", content, readErr)
	}
	if _, statErr := os.Stat(exePath + ".update-pending"); !os.IsNotExist(statErr) {
		t.Error("update-pending marker survived a sync failure")
	}
}

// A session that lands while the watchdog timer is already firing must win
// the armedUpdate CompareAndSwap: losing it stops the callback so a build
// that just joined is not rolled back.
func TestWatchdogDoesNotRollBackJoinedBuild(t *testing.T) {
	origExe, origTimeout := osExecutable, updateJoinTimeout
	defer func() {
		osExecutable = origExe
		updateJoinTimeout = origTimeout
		if timer := updateWatchdog.Swap(nil); timer != nil {
			timer.Stop()
		}
		armedUpdate.Store(nil)
	}()
	exePath := stageExecutable(t)
	if err := os.WriteFile(exePath, []byte("unproven binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".prev", []byte("previous binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath+".update-pending", mustJSON(pendingUpdate{Version: "1.2.3"}), 0600); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return exePath, nil }

	exited := make(chan int, 1)
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) { exited <- code }
	updateJoinTimeout = 10 * time.Millisecond

	if p := checkPendingUpdate(); p == nil {
		t.Fatal("pending update was not armed")
	}
	// The join lands while the callback is in flight: updateJoined's Swap
	// removes the arm before the callback reaches its CompareAndSwap.
	armedUpdate.Store(nil)

	select {
	case code := <-exited:
		t.Fatalf("watchdog rolled back a build that joined: osExit(%d)", code)
	case <-time.After(200 * time.Millisecond):
	}
	content, err := os.ReadFile(exePath)
	if err != nil || string(content) != "unproven binary" {
		t.Errorf("joined build was rolled back: %q, err %v", content, err)
	}
	if res := readUpdateResult(); res != nil && res.Error != "" {
		t.Errorf("failure recorded for a build that joined: %+v", res)
	}
}

// beginUpdate registers exactly one update, detached from the requesting
// session but cancellable by the shutdown hook; finish releases the slot.
func TestBeginUpdateRegistrationAndShutdownCancel(t *testing.T) {
	t.Cleanup(func() { currentUpdate.Store(nil) })
	currentUpdate.Store(nil)

	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	defer sessionCancel()

	u := beginUpdate(sessionCtx)
	if u == nil {
		t.Fatal("beginUpdate returned nil with no update registered")
	}
	// The update must survive session cancellation...
	sessionCancel()
	if u.ctx.Err() != nil {
		t.Fatalf("update ctx = %v, want it detached from the session", u.ctx.Err())
	}
	// ...but a duplicate update must be refused.
	if again := beginUpdate(context.Background()); again != nil {
		t.Fatal("beginUpdate handed out a second update handle")
	}

	// Shutdown cancels the registered update with its own cause.
	cancelActiveUpdate()
	if u.ctx.Err() == nil {
		t.Fatal("cancelActiveUpdate did not cancel the update")
	}
	if cause := context.Cause(u.ctx); !errors.Is(cause, errUpdateShutdown) {
		t.Fatalf("update cancellation cause = %v, want %v", cause, errUpdateShutdown)
	}

	// finish clears the registration so a later update can begin.
	u.finish()
	if got := currentUpdate.Load(); got != nil {
		t.Fatal("finish left the update registered")
	}
	next := beginUpdate(context.Background())
	if next == nil {
		t.Fatal("beginUpdate refused a new update after finish")
	}
	next.finish()
}

// waitActiveUpdate returns as soon as the registered update finishes, and
// without waiting at all when no update is running.
func TestWaitActiveUpdateReturnsWhenUpdateFinishes(t *testing.T) {
	t.Cleanup(func() { currentUpdate.Store(nil) })
	currentUpdate.Store(nil)

	start := time.Now()
	waitActiveUpdate(200 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("waitActiveUpdate with no update waited %v", elapsed)
	}

	u := beginUpdate(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		u.finish()
	}()
	start = time.Now()
	waitActiveUpdate(2 * time.Second)
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatal("waitActiveUpdate timed out although the update finished")
	}
}

// A shutdown cancellation landing between the binary swap and the re-exec
// — exactly where SIGTERM during the drain arrives — must restore the
// previous build instead of re-execing into the new one.
func TestSelfUpdateShutdownBeforeExecRestoresPrev(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	// Register the update the way the session's update handler does, then
	// cancel it from the drain hook: the shutdown hook runs while the
	// update is between the swap and the exec.
	u := beginUpdate(context.Background())
	t.Cleanup(u.finish)

	execCalled := false
	syscallExec = func(string, []string, []string) error {
		execCalled = true
		return nil
	}
	drain := func(context.Context) bool {
		cancelActiveUpdate() // SIGTERM lands during the drain
		return true
	}
	origDrain := drainResultSpool.Load()
	drainResultSpool.Store(&drain)
	t.Cleanup(func() { drainResultSpool.Store(origDrain) })

	err := selfUpdateContext(u.ctx, downloadURL, checksum, "1.2.3")
	if err == nil || !errors.Is(err, errUpdateShutdown) {
		t.Fatalf("selfUpdate error = %v, want the shutdown cause", err)
	}
	if execCalled {
		t.Error("re-exec ran although shutdown cancelled the update")
	}
	content, readErr := os.ReadFile(exePath)
	if readErr != nil || string(content) != "previous binary" {
		t.Errorf("previous binary not restored: content %q, err %v", content, readErr)
	}
	if _, statErr := os.Stat(exePath + ".update-pending"); !os.IsNotExist(statErr) {
		t.Error("update-pending marker survived the shutdown cancellation")
	}
}

// waitActiveUpdate must give up when the cancelled update never returns:
// shutdown proceeds instead of hanging on a stalled goroutine.
func TestWaitActiveUpdateTimesOutWhenUpdateStalls(t *testing.T) {
	t.Cleanup(func() { currentUpdate.Store(nil) })
	currentUpdate.Store(nil)

	u := beginUpdate(context.Background())
	t.Cleanup(u.finish)

	start := time.Now()
	waitActiveUpdate(time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitActiveUpdate blocked %v on a stalled update", elapsed)
	}
}

// A sync failure whose restore also fails must surface both errors: the
// operator has to know the previous build could not be put back either.
func TestSelfUpdateSyncFailureWithFailedRestore(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	origSync := syncDirectory
	t.Cleanup(func() { syncDirectory = origSync })
	syncDirectory = func(string) error { return errors.New("dirsync failed") }

	// The staged build lands; only the restore of the previous build fails.
	osRename = func(oldpath, newpath string) error {
		if oldpath == exePath+".prev" && newpath == exePath {
			return errors.New("device busy")
		}
		return os.Rename(oldpath, newpath)
	}

	err := selfUpdateContext(context.Background(), downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "sync executable directory") {
		t.Fatalf("selfUpdate error = %v, want directory sync failure", err)
	}
	if !strings.Contains(err.Error(), "and restore failed") {
		t.Errorf("error %v does not name the failed restore", err)
	}
}

// A shutdown cancellation landing after the swap with a failing restore must
// still report the cancellation and drop the marker: the next boot must not
// be treated as running an unproven build.
func TestSelfUpdateShutdownCancelWithFailedRestore(t *testing.T) {
	forceBareBinaryUpdate(t)
	body := elfUpdateBodyForHost()
	srv, downloadURL, checksum := updateTestServer(t, body)
	exePath := stageExecutable(t)
	stubUpdateIO(t, srv, exePath)

	// Register the update the way the session's update handler does, then
	// cancel it from the drain hook: the window between the binary swap
	// and the re-exec that a shutdown during the drain produces.
	u := beginUpdate(context.Background())
	t.Cleanup(u.finish)

	execCalled := false
	syscallExec = func(string, []string, []string) error {
		execCalled = true
		return nil
	}
	// The staged build lands; only the shutdown-triggered restore fails.
	osRename = func(oldpath, newpath string) error {
		if oldpath == exePath+".prev" && newpath == exePath {
			return errors.New("device busy")
		}
		return os.Rename(oldpath, newpath)
	}
	drain := func(context.Context) bool {
		cancelActiveUpdate() // SIGTERM lands during the drain
		return true
	}
	origDrain := drainResultSpool.Load()
	drainResultSpool.Store(&drain)
	t.Cleanup(func() { drainResultSpool.Store(origDrain) })

	err := selfUpdateContext(u.ctx, downloadURL, checksum, "1.2.3")
	if err == nil || !strings.Contains(err.Error(), "update canceled before re-exec") {
		t.Fatalf("selfUpdate error = %v, want the shutdown cancellation", err)
	}
	if execCalled {
		t.Error("re-exec ran although shutdown cancelled the update")
	}
	if _, statErr := os.Stat(exePath + ".update-pending"); !os.IsNotExist(statErr) {
		t.Error("update-pending marker survived the cancelled update")
	}
}
