// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyStoreTOFU(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	s := newHostKeyStore(path)

	// First connection should succeed (trust on first use)
	if err := s.verify("10.0.0.1:22", "abc123"); err != nil {
		t.Fatalf("first connect should succeed: %v", err)
	}

	// Same key should succeed
	if err := s.verify("10.0.0.1:22", "abc123"); err != nil {
		t.Fatalf("same key should succeed: %v", err)
	}

	// Different key should fail
	if err := s.verify("10.0.0.1:22", "different"); err == nil {
		t.Fatal("changed key should fail")
	}

	// New host should succeed
	if err := s.verify("10.0.0.2:22", "def456"); err != nil {
		t.Fatalf("new host should succeed: %v", err)
	}
}

func TestHostKeyStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")

	s1 := newHostKeyStore(path)
	_ = s1.verify("host1:22", "fp1")

	// Load from same file
	s2 := newHostKeyStore(path)
	if err := s2.verify("host1:22", "fp1"); err != nil {
		t.Fatalf("persisted key should match: %v", err)
	}
	if err := s2.verify("host1:22", "changed"); err == nil {
		t.Fatal("changed key should fail after reload")
	}
}

func TestHostKeyStoreMissingFile(t *testing.T) {
	s := newHostKeyStore("/nonexistent/path/known_hosts.json")
	if err := s.verify("host:22", "fp"); err == nil {
		t.Fatal("expected error when trusted key cannot be persisted")
	}
}

func TestHostKeyStoreCorruptFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newHostKeyStore(path)
	if err := s.verify("host:22", "new-fingerprint"); err == nil {
		t.Fatal("corrupt host-key store allowed first-use trust")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "not json" {
		t.Fatalf("corrupt store was overwritten: %q", data)
	}
}

func TestHostKeyStoreConcurrency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	s := newHostKeyStore(path)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.verify("host:22", "fp1")
		}()
	}
	wg.Wait()
}

func TestInitHostKeyStore(t *testing.T) {
	t.Run("malformed store", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hosts.json")
		if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
			t.Fatal(err)
		}
		original := globalHostKeys
		sentinel := &hostKeyStore{}
		globalHostKeys = sentinel
		t.Cleanup(func() { globalHostKeys = original })

		err := initHostKeyStore(path)
		if err == nil || !strings.Contains(err.Error(), "parse host key store") {
			t.Fatalf("initHostKeyStore() error = %v, want malformed-store error", err)
		}
		if globalHostKeys != sentinel {
			t.Fatal("failed initialization replaced the installed store")
		}
	})

	t.Run("unwritable directory", func(t *testing.T) {
		originalStore := globalHostKeys
		sentinel := &hostKeyStore{}
		globalHostKeys = sentinel
		t.Cleanup(func() { globalHostKeys = originalStore })

		originalCreateTemp := hostKeyCreateTemp
		hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) {
			return nil, os.ErrPermission
		}
		t.Cleanup(func() { hostKeyCreateTemp = originalCreateTemp })

		path := filepath.Join(t.TempDir(), "hosts.json")
		err := initHostKeyStore(path)
		if err == nil {
			t.Fatal("initHostKeyStore() succeeded for an unwritable directory")
		}
		if !strings.Contains(err.Error(), "host key store "+path) {
			t.Fatalf("initHostKeyStore() error = %q, want path context", err)
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("initHostKeyStore() error = %v, want permission error", err)
		}
		if globalHostKeys != sentinel {
			t.Fatal("failed initialization replaced the installed store")
		}
	})

	t.Run("success", func(t *testing.T) {
		original := globalHostKeys
		t.Cleanup(func() { globalHostKeys = original })

		path := filepath.Join(t.TempDir(), "hosts.json")
		if err := initHostKeyStore(path); err != nil {
			t.Fatalf("initHostKeyStore() error = %v", err)
		}
		store := getHostKeyStore()
		if store == nil {
			t.Fatal("getHostKeyStore() returned nil")
		}
		if store.path != path {
			t.Fatalf("installed store path = %q, want %q", store.path, path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("initialized store was not persisted: %v", err)
		}
	})
}

func TestSSHHostKeyCallbackLegacyAndNamespacedKeys(t *testing.T) {
	original := globalHostKeys
	t.Cleanup(func() { globalHostKeys = original })

	trustedKey := hmTSSHPublicKey(t)
	changedKey := hmTSSHPublicKey(t)
	legacyAddress := "127.0.0.1:22"
	path := filepath.Join(t.TempDir(), "hosts.json")
	legacyKeys := map[string]string{
		legacyAddress: fmt.Sprintf("%x", sha256.Sum256(trustedKey.Marshal())),
	}
	data, err := json.Marshal(legacyKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	globalHostKeys = newHostKeyStore(path)

	callback := sshHostKeyCallback()
	legacyRemote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("", legacyRemote, trustedKey); err != nil {
		t.Fatalf("legacy host key was rejected: %v", err)
	}
	if err := callback("", legacyRemote, changedKey); err == nil {
		t.Fatal("changed legacy host key was accepted")
	} else if !strings.Contains(err.Error(), "TOFU: host key changed for ssh:"+legacyAddress) {
		t.Fatalf("mismatch error = %q, want namespaced host", err)
	}

	newAddress := "192.0.2.1:22"
	newRemote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback("", newRemote, changedKey); err != nil {
		t.Fatalf("first-use host key was rejected: %v", err)
	}
	persistedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]string
	if err := json.Unmarshal(persistedData, &persisted); err != nil {
		t.Fatal(err)
	}
	if _, ok := persisted["ssh:"+newAddress]; !ok {
		t.Fatalf("first-use key was not stored under %q: %v", "ssh:"+newAddress, persisted)
	}
	if _, ok := persisted[newAddress]; ok {
		t.Fatalf("first-use key was stored under legacy name %q", newAddress)
	}
}

func TestHostKeyStoreSaveError(t *testing.T) {
	// Use a path in a non-existent directory
	s := newHostKeyStore("/nonexistent/dir/hosts.json")
	if err := s.verify("host:22", "fp"); err == nil {
		t.Fatal("expected persistence error")
	}
	if _, ok := s.keys["host:22"]; ok {
		t.Fatal("failed first-use trust should not remain cached in memory")
	}
}

func TestTlsCertFingerprint(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("test certificate data"),
	}
	fp := tlsCertFingerprint(cert)
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
	// Verify it's a hex-encoded SHA256 (64 chars)
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %s", len(fp), fp)
	}
	// Same input should produce same output
	fp2 := tlsCertFingerprint(cert)
	if fp != fp2 {
		t.Error("fingerprint not deterministic")
	}
}

// hmTFailingTempFile is an injectable hostKeyTempFile whose Write, Sync and
// Close outcomes are individually controllable.
type hmTFailingTempFile struct {
	name      string
	writeErr  error
	syncErr   error
	closeErr  error
	written   []byte
	syncCalls int
	closed    bool
}

func (f *hmTFailingTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = append(f.written, p...)
	return len(p), nil
}

func (f *hmTFailingTempFile) Name() string { return f.name }

func (f *hmTFailingTempFile) Sync() error {
	f.syncCalls++
	return f.syncErr
}

func (f *hmTFailingTempFile) Close() error {
	f.closed = true
	return f.closeErr
}

func hmTSSHPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("convert SSH key: %v", err)
	}
	return key
}

// hmTNewStore returns a store rooted in a fresh temp dir plus its path.
func hmTNewStore(t *testing.T) (*hostKeyStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	return newHostKeyStore(path), path
}

func TestHmNewHostKeyStoreUnreadablePath(t *testing.T) {
	// A directory makes os.ReadFile fail with EISDIR, which is not IsNotExist.
	dir := t.TempDir()
	s := newHostKeyStore(dir)
	if s.loadErr == nil {
		t.Fatal("expected loadErr for unreadable store path")
	}
	if !strings.Contains(s.loadErr.Error(), "read host key store") {
		t.Fatalf("unexpected loadErr: %v", s.loadErr)
	}
	// verify must fail closed and must not mutate the in-memory map.
	err := s.verify("host:22", "fp")
	if err == nil || !strings.Contains(err.Error(), "read host key store") {
		t.Fatalf("expected verify to surface loadErr, got %v", err)
	}
	if len(s.keys) != 0 {
		t.Fatalf("expected no keys cached, got %v", s.keys)
	}
}

func TestHmNewHostKeyStoreCorruptJSONLoadErr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newHostKeyStore(path)
	if s.loadErr == nil {
		t.Fatal("expected loadErr for corrupt store")
	}
	if !strings.Contains(s.loadErr.Error(), "parse host key store") {
		t.Fatalf("unexpected loadErr: %v", s.loadErr)
	}
}

func TestHmVerifyMismatchMentionsMITM(t *testing.T) {
	s, _ := hmTNewStore(t)
	if err := s.verify("10.0.0.9:22", "aaaa"); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	err := s.verify("10.0.0.9:22", "bbbb")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	for _, want := range []string{"possible MITM", "stored=aaaa", "got=bbbb"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if s.keys["10.0.0.9:22"] != "aaaa" {
		t.Fatalf("mismatch must not overwrite the stored key, got %q", s.keys["10.0.0.9:22"])
	}
}

func TestHmSaveMarshalError(t *testing.T) {
	orig := hostKeyMarshal
	defer func() { hostKeyMarshal = orig }()
	hostKeyMarshal = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal boom")
	}

	s, _ := hmTNewStore(t)
	err := s.verify("h:22", "fp")
	if err == nil || !strings.Contains(err.Error(), "marshal boom") {
		t.Fatalf("expected marshal error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to persist trusted host key") {
		t.Fatalf("expected wrapped persistence error, got %v", err)
	}
	if _, ok := s.keys["h:22"]; ok {
		t.Fatal("failed save must roll the key back out of memory")
	}
}

func TestHmSaveCreateTempError(t *testing.T) {
	// filepath.Dir of a path in a missing directory makes os.CreateTemp fail.
	s := newHostKeyStore(filepath.Join(t.TempDir(), "missing", "known_hosts.json"))
	err := s.save()
	if err == nil {
		t.Fatal("expected CreateTemp error")
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHmSaveTempFileFailures(t *testing.T) {
	tests := []struct {
		name       string
		file       *hmTFailingTempFile
		wantErr    string
		wantClosed bool
	}{
		{
			name:       "write fails",
			file:       &hmTFailingTempFile{name: "unused", writeErr: errors.New("write boom")},
			wantErr:    "write boom",
			wantClosed: true,
		},
		{
			name:       "sync fails",
			file:       &hmTFailingTempFile{name: "unused", syncErr: errors.New("sync boom")},
			wantErr:    "sync boom",
			wantClosed: true,
		},
		{
			name:       "close fails",
			file:       &hmTFailingTempFile{name: "unused", closeErr: errors.New("close boom")},
			wantErr:    "close boom",
			wantClosed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.file.name = filepath.Join(dir, ".known_hosts.json-tmp")

			orig := hostKeyCreateTemp
			defer func() { hostKeyCreateTemp = orig }()
			hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) { return tt.file, nil }

			s := newHostKeyStore(filepath.Join(dir, "known_hosts.json"))
			s.keys["h:22"] = "fp"
			err := s.save()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q, got %v", tt.wantErr, err)
			}
			if tt.file.closed != tt.wantClosed {
				t.Fatalf("closed=%v, want %v", tt.file.closed, tt.wantClosed)
			}
			if _, statErr := os.Stat(s.path); !os.IsNotExist(statErr) {
				t.Fatalf("failed save must not create the store file: %v", statErr)
			}
		})
	}
}

func TestHmSaveRenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	// A directory at the destination makes os.Rename fail after a clean write.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	s := &hostKeyStore{path: path, keys: map[string]string{"h:22": "fp"}}
	err := s.save()
	if err == nil {
		t.Fatal("expected rename error")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Fatalf("unexpected error: %v", err)
	}
	// The temp file must have been cleaned up by the deferred Remove.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "known_hosts.json" {
		t.Fatalf("temp file leaked: %v", entries)
	}
}

func TestHmSaveSuccessWritesAtomically(t *testing.T) {
	s, path := hmTNewStore(t)
	if err := s.verify("h:22", "fp"); err != nil {
		t.Fatalf("first use should persist: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("store is not valid JSON: %v", err)
	}
	if got["h:22"] != "fp" {
		t.Fatalf("expected persisted fingerprint, got %v", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the store file, got %v", entries)
	}
}
