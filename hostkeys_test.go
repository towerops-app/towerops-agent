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
	"time"

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
	// Entries are stored as "<key type> <fingerprint>" so the algorithm can be
	// pinned on later dials; legacy entries migrate to this form on verify.
	if got, want := persisted["ssh:"+legacyAddress], trustedKey.Type()+" "+legacyKeys[legacyAddress]; got != want {
		t.Fatalf("legacy key migrated to %q = %q, want %q: %v", "ssh:"+legacyAddress, got, want, persisted)
	}
	if _, ok := persisted[legacyAddress]; ok {
		t.Fatalf("migrated key remained under legacy name %q", legacyAddress)
	}
	if got, want := persisted["ssh:"+newAddress], changedKey.Type()+" "+fmt.Sprintf("%x", sha256.Sum256(changedKey.Marshal())); got != want {
		t.Fatalf("first-use key stored as %q = %q, want %q: %v", "ssh:"+newAddress, got, want, persisted)
	}
	if _, ok := persisted[newAddress]; ok {
		t.Fatalf("first-use key was stored under legacy name %q", newAddress)
	}
}

func TestHostKeyStoreLegacyMigrationRollsBackOnSaveFailure(t *testing.T) {
	const (
		legacyHost  = "192.0.2.5:22"
		fingerprint = "trusted"
	)
	s := &hostKeyStore{
		path: filepath.Join(t.TempDir(), "known_hosts.json"),
		keys: map[string]string{legacyHost: fingerprint},
	}
	originalMarshal := hostKeyMarshal
	hostKeyMarshal = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	t.Cleanup(func() { hostKeyMarshal = originalMarshal })

	// A matching SSH key must verify even when migrating the legacy entry to
	// its typed namespaced form cannot be persisted.
	if err := s.verifyKey("ssh:"+legacyHost, fingerprint, ssh.KeyAlgoED25519); err != nil {
		t.Fatalf("matching legacy key was rejected after migration save failure: %v", err)
	}
	if got := s.keys[legacyHost]; got != fingerprint {
		t.Fatalf("legacy key was not restored after failed migration: %v", s.keys)
	}
	if _, ok := s.keys["ssh:"+legacyHost]; ok {
		t.Fatalf("namespaced key remained after failed migration: %v", s.keys)
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
	err := s.persist(true)
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
		{
			// Every write step succeeds but the temp file is gone before the
			// pre-rename stat, so persist must fail rather than rename.
			name:       "stat of temp file fails",
			file:       &hmTFailingTempFile{name: "unused"},
			wantErr:    "no such file",
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
			err := s.persist(true)
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
	err := s.persist(true)
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

// TestHostKeyStorePinnedKeyAlgorithm covers the typed store entry that lets
// executeMikrotikBackupContext pin HostKeyAlgorithms: first-use records the
// presented key type, legacy and untyped entries yield "" until a successful
// verify migrates them, and a nil store is safe for pre-init calls.
func TestHostKeyStorePinnedKeyAlgorithm(t *testing.T) {
	s, _ := hmTNewStore(t)
	key := hmTSSHPublicKey(t)
	host := "ssh:192.0.2.7:22"

	if got := s.pinnedKeyAlgorithm(host); got != "" {
		t.Fatalf("unpinned host algorithm = %q, want empty", got)
	}
	if got := (*hostKeyStore)(nil).pinnedKeyAlgorithm(host); got != "" {
		t.Fatalf("nil store algorithm = %q, want empty", got)
	}

	if err := s.verifySSHKey(host, key); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if got, want := s.pinnedKeyAlgorithm(host), ssh.KeyAlgoED25519; got != want {
		t.Fatalf("pinned algorithm = %q, want %q", got, want)
	}
	if got, want := s.keys[host], ssh.KeyAlgoED25519+" "+fmt.Sprintf("%x", sha256.Sum256(key.Marshal())); got != want {
		t.Fatalf("stored entry = %q, want %q", got, want)
	}

	// A TLS entry stores no key type, so it never pins SSH algorithms.
	tlsHost := "tls:192.0.2.7:8729"
	if err := s.verify(tlsHost, "certfp"); err != nil {
		t.Fatalf("tls verify failed: %v", err)
	}
	if got := s.pinnedKeyAlgorithm(tlsHost); got != "" {
		t.Fatalf("tls entry algorithm = %q, want empty", got)
	}

	// A legacy (un-namespaced) entry matches, then migrates to the typed
	// namespaced form.
	legacyHost := "ssh:192.0.2.8:22"
	s.keys["192.0.2.8:22"] = fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
	if got := s.pinnedKeyAlgorithm(legacyHost); got != "" {
		t.Fatalf("legacy entry algorithm = %q, want empty before migration", got)
	}
	if err := s.verifySSHKey(legacyHost, key); err != nil {
		t.Fatalf("legacy verify failed: %v", err)
	}
	if got := s.pinnedKeyAlgorithm(legacyHost); got != ssh.KeyAlgoED25519 {
		t.Fatalf("post-migration algorithm = %q, want ssh-ed25519", got)
	}
	if _, ok := s.keys["192.0.2.8:22"]; ok {
		t.Fatal("legacy entry was not migrated")
	}
}

// TestHostKeyStoreForget covers the recovery path behind --forget-host-key:
// "ip:port" clears the ssh:, tls: and legacy forms at once, a verbatim
// namespaced key removes only itself, unknown hosts report not-found, and a
// save failure restores the entry.
func TestHostKeyStoreForget(t *testing.T) {
	s, path := hmTNewStore(t)
	key := hmTSSHPublicKey(t)
	fp := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
	for _, h := range []string{"ssh:192.0.2.9:22", "tls:192.0.2.9:8729", "192.0.2.9:22"} {
		if err := s.verifyKey(h, fp, ""); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	removed, err := s.forget("192.0.2.9:22")
	if err != nil || !removed {
		t.Fatalf("forget = %v, %v; want true, nil", removed, err)
	}
	if len(s.keys) != 1 {
		t.Fatalf("expected only tls: entry to survive, got %v", s.keys)
	}
	if _, ok := s.keys["tls:192.0.2.9:8729"]; !ok {
		t.Fatalf("tls entry wrongly removed: %v", s.keys)
	}

	removed, err = s.forget("tls:192.0.2.9:8729")
	if err != nil || !removed {
		t.Fatalf("forget tls: = %v, %v; want true, nil", removed, err)
	}
	removed, err = s.forget("192.0.2.9:22")
	if err != nil || removed {
		t.Fatalf("forget unknown = %v, %v; want false, nil", removed, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]string
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 0 {
		t.Fatalf("store file still holds entries: %v", persisted)
	}
}

// TestHostKeyStoreReadsDoNotWaitOnSave: with the durable write split behind
// saveMu, map reads (pinnedKeyAlgorithm) and mismatch rejects must not block
// behind another verify's in-flight fsync — only the mutating caller awaits
// its save.
func TestHostKeyStoreReadsDoNotWaitOnSave(t *testing.T) {
	s, _ := hmTNewStore(t)
	key := hmTSSHPublicKey(t)

	// Seed a durable typed entry plus a plain entry for the mismatch check.
	if err := s.verifySSHKey("ssh:192.0.2.10:22", key); err != nil {
		t.Fatalf("seed: %v", err)
	}

	release := make(chan struct{})
	// Deferred so a failing read assertion cannot leave the verify goroutine
	// parked inside save() forever; the explicit call below unblocks the
	// success path first.
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer closeRelease()
	started := make(chan struct{}, 8)
	original := hostKeyCreateTemp
	t.Cleanup(func() { hostKeyCreateTemp = original })
	hostKeyCreateTemp = func(dir, pattern string) (hostKeyTempFile, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return original(dir, pattern)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.verifySSHKey("ssh:192.0.2.11:22", key)
	}()
	<-started // the first-use verify is now parked inside save()

	fast := make(chan string, 2)
	go func() {
		fast <- s.pinnedKeyAlgorithm("ssh:192.0.2.10:22")
	}()
	go func() {
		if err := s.verify("ssh:192.0.2.10:22", "different-fingerprint"); err != nil {
			fast <- "mismatch-rejected"
		} else {
			fast <- "mismatch-accepted"
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case got := <-fast:
			switch got {
			case ssh.KeyAlgoED25519, "mismatch-rejected":
			default:
				t.Fatalf("unexpected read result %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("read blocked behind an in-flight save")
		}
	}

	closeRelease()
	if err := <-done; err != nil {
		t.Fatalf("first-use verify failed after release: %v", err)
	}
	if got := s.keys["ssh:192.0.2.11:22"]; got == "" {
		t.Fatalf("new host key was not stored: %v", s.keys)
	}
}

// TestHostKeyStoreSavedGenCoverage exercises the "a concurrent save already
// persisted this generation" guards that keep verifyKey and forget from
// rolling back mutations another save already wrote. The test drives savedGen
// ahead under mu to stand in for that concurrent save.
func TestHostKeyStoreSavedGenCoverage(t *testing.T) {
	failSave := func(t *testing.T) {
		t.Helper()
		orig := hostKeyCreateTemp
		t.Cleanup(func() { hostKeyCreateTemp = orig })
		hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) {
			return nil, errors.New("create temp failed")
		}
	}
	// failSaveCovered fails this save after advancing savedGen to the current
	// generation, standing in for a concurrent save that wrote the mutation
	// between this caller's snapshot and its post-failure check. Setting
	// savedGen before the mutation would not work: persist would see the
	// generation covered and return nil without ever failing.
	failSaveCovered := func(t *testing.T, s *hostKeyStore) {
		t.Helper()
		orig := hostKeyCreateTemp
		t.Cleanup(func() { hostKeyCreateTemp = orig })
		hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) {
			s.mu.Lock()
			s.savedGen = s.gen
			s.mu.Unlock()
			return nil, errors.New("create temp failed")
		}
	}

	t.Run("first-use save failure with fresh savedGen rolls back", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		failSave(t)
		err := s.verify("ssh:192.0.2.20:22", "fp20")
		if err == nil {
			t.Fatal("expected persist failure")
		}
		if _, ok := s.keys["ssh:192.0.2.20:22"]; ok {
			t.Fatal("rolled-back entry still present")
		}
	})

	t.Run("first-use save failure superseded by concurrent save keeps entry", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		failSaveCovered(t, s)
		if err := s.verify("ssh:192.0.2.21:22", "fp21"); err != nil {
			t.Fatalf("expected nil for superseded save failure, got %v", err)
		}
	})

	t.Run("migration save failure superseded returns nil", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		key := hmTSSHPublicKey(t)
		fp := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
		// A typed namespaced entry seeded untyped migrates on verify.
		s.keys["ssh:192.0.2.22:22"] = fp
		failSaveCovered(t, s)
		if err := s.verifySSHKey("ssh:192.0.2.22:22", key); err != nil {
			t.Fatalf("expected nil for superseded migration failure, got %v", err)
		}
	})

	t.Run("untyped-entry migration save failure keeps verify working", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		key := hmTSSHPublicKey(t)
		fp := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
		s.keys["ssh:192.0.2.24:22"] = fp // untyped: written by an older release
		failSave(t)
		if err := s.verifySSHKey("ssh:192.0.2.24:22", key); err != nil {
			t.Fatalf("untyped migration must not fail the verify: %v", err)
		}
		if s.keys["ssh:192.0.2.24:22"] != fp {
			t.Fatal("untyped entry was not restored after failed migration")
		}
	})

	t.Run("typed-entry verify saves again when savedGen lags", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		key := hmTSSHPublicKey(t)
		if err := s.verifySSHKey("ssh:192.0.2.25:22", key); err != nil {
			t.Fatalf("seed: %v", err)
		}
		// Mark the entry unsaved so the matching-entry path must save.
		s.mu.Lock()
		s.pending["ssh:192.0.2.25:22"] = s.gen
		s.savedGen = 0
		s.mu.Unlock()
		if err := s.verifySSHKey("ssh:192.0.2.25:22", key); err != nil {
			t.Fatalf("repeat verify failed: %v", err)
		}
	})

	t.Run("typed-entry verify fails closed when the save fails", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		key := hmTSSHPublicKey(t)
		if err := s.verifySSHKey("ssh:192.0.2.26:22", key); err != nil {
			t.Fatalf("seed: %v", err)
		}
		failSave(t)
		s.mu.Lock()
		s.pending["ssh:192.0.2.26:22"] = s.gen
		s.savedGen = 0
		s.mu.Unlock()
		if err := s.verifySSHKey("ssh:192.0.2.26:22", key); err == nil {
			t.Fatal("expected save failure to propagate")
		}
	})

	t.Run("forget reports a loadErr store", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		s.loadErr = errors.New("store unreadable")
		if removed, err := s.forget("ssh:192.0.2.27:22"); err == nil || removed {
			t.Fatalf("forget = %v, %v; want false with loadErr", removed, err)
		}
	})

	t.Run("forget save failure superseded reports removed", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		s.keys["ssh:192.0.2.28:22"] = "fp28"
		failSaveCovered(t, s)
		if removed, err := s.forget("ssh:192.0.2.28:22"); err != nil || !removed {
			t.Fatalf("forget = %v, %v; want true, nil", removed, err)
		}
	})

	t.Run("forget save failure restores removed keys", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		s.keys["ssh:192.0.2.29:22"] = "fp29"
		failSave(t)
		if removed, err := s.forget("ssh:192.0.2.29:22"); err == nil || removed {
			t.Fatalf("forget = %v, %v; want false, err", removed, err)
		}
		if s.keys["ssh:192.0.2.29:22"] != "fp29" {
			t.Fatal("removed key was not restored after save failure")
		}
	})

	t.Run("pinnedKeyAlgorithm returns empty on a broken store", func(t *testing.T) {
		s, _ := hmTNewStore(t)
		s.loadErr = errors.New("store unreadable")
		s.keys["ssh:192.0.2.30:22"] = "ssh-ed25519 fp30"
		if got := s.pinnedKeyAlgorithm("ssh:192.0.2.30:22"); got != "" {
			t.Fatalf("pinnedKeyAlgorithm = %q, want empty", got)
		}
	})
}

func TestHostKeyStoreSaveFailsOnDirectorySync(t *testing.T) {
	s, _ := hmTNewStore(t)
	orig := syncDirectory
	t.Cleanup(func() { syncDirectory = orig })
	syncDirectory = func(string) error { return errors.New("dir sync failed") }

	if err := s.verify("ssh:192.0.2.31:22", "fp31"); err == nil {
		t.Fatal("expected directory-sync failure to propagate")
	}
}

// TestHostKeyStoreFailedFirstUseKeepsTrustedMatchesOffDisk: a failed first-use
// save rolls back only its own entry, so later matches on already-durable
// entries neither write nor inherit the save failure (a full or read-only
// disk must not fail every known device closed).
func TestHostKeyStoreFailedFirstUseKeepsTrustedMatchesOffDisk(t *testing.T) {
	s, _ := hmTNewStore(t)
	if err := s.verify("ssh:192.0.2.40:22", "fp40"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	orig := hostKeyCreateTemp
	t.Cleanup(func() { hostKeyCreateTemp = orig })
	calls := 0
	hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) {
		calls++
		return nil, errors.New("disk full")
	}

	if err := s.verify("ssh:192.0.2.41:22", "fp41"); err == nil {
		t.Fatal("first-use with failing save must fail closed")
	}
	calls = 0
	for i := 0; i < 3; i++ {
		if err := s.verify("ssh:192.0.2.40:22", "fp40"); err != nil {
			t.Fatalf("match on a durable entry after a failed first-use: %v", err)
		}
	}
	if calls != 0 {
		t.Fatalf("matches on a durable entry wrote %d times, want 0", calls)
	}
}

// TestHostKeyStoreSaveSkipsCoveredGeneration: a save whose mutation another
// save already persisted returns without another fsync.
func TestHostKeyStoreSaveSkipsCoveredGeneration(t *testing.T) {
	s, _ := hmTNewStore(t)
	if err := s.verify("ssh:192.0.2.42:22", "fp42"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	orig := hostKeyCreateTemp
	t.Cleanup(func() { hostKeyCreateTemp = orig })
	hostKeyCreateTemp = func(string, string) (hostKeyTempFile, error) {
		t.Fatal("save rewrote an already-persisted generation")
		return nil, nil
	}
	if err := s.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
}

// TestHostKeyStoreRespectsOutOfProcessForget: a running store must not
// resurrect an entry --forget-host-key removed from the file, and must accept
// the device's new key without a restart.
func TestHostKeyStoreRespectsOutOfProcessForget(t *testing.T) {
	daemon, path := hmTNewStore(t)
	for _, h := range []string{"ssh:192.0.2.50:22", "ssh:192.0.2.51:22"} {
		if err := daemon.verify(h, "old-"+h); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	// The CLI forgets one entry from a separate store instance.
	if code := runForgetHostKeys(path, []string{"192.0.2.50:22"}); code != 0 {
		t.Fatalf("forget exit = %d", code)
	}

	// An unrelated first-use in the daemon saves the whole map.
	if err := daemon.verify("ssh:192.0.2.52:22", "fp52"); err != nil {
		t.Fatalf("first-use: %v", err)
	}
	persisted := hmTReadStore(t, path)
	if _, ok := persisted["ssh:192.0.2.50:22"]; ok {
		t.Fatalf("daemon save resurrected a forgotten entry: %v", persisted)
	}
	if persisted["ssh:192.0.2.51:22"] == "" || persisted["ssh:192.0.2.52:22"] == "" {
		t.Fatalf("merge dropped entries: %v", persisted)
	}

	// Forget again, then the device presents a new key: the daemon re-reads
	// the changed file instead of rejecting it as a MITM.
	if code := runForgetHostKeys(path, []string{"192.0.2.51:22"}); code != 0 {
		t.Fatalf("forget exit = %d", code)
	}
	if err := daemon.verify("ssh:192.0.2.51:22", "new-key"); err != nil {
		t.Fatalf("new key after out-of-process forget rejected: %v", err)
	}
	if got := hmTReadStore(t, path)["ssh:192.0.2.51:22"]; got != "new-key" {
		t.Fatalf("re-trusted entry = %q, want new-key", got)
	}

	// A real mismatch is still rejected.
	if err := daemon.verify("ssh:192.0.2.52:22", "attacker"); err == nil {
		t.Fatal("mismatch accepted")
	}
}

// TestHostKeyStorePinRefreshesAfterOutOfProcessForget: the pinned algorithm
// is dropped once the entry is forgotten on disk, so a device with a new key
// type can negotiate.
func TestHostKeyStorePinRefreshesAfterOutOfProcessForget(t *testing.T) {
	daemon, path := hmTNewStore(t)
	key := hmTSSHPublicKey(t)
	if err := daemon.verifySSHKey("ssh:192.0.2.53:22", key); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := daemon.pinnedKeyAlgorithm("ssh:192.0.2.53:22"); got != ssh.KeyAlgoED25519 {
		t.Fatalf("pin = %q", got)
	}
	if code := runForgetHostKeys(path, []string{"192.0.2.53:22"}); code != 0 {
		t.Fatalf("forget exit = %d", code)
	}
	if got := daemon.pinnedKeyAlgorithm("ssh:192.0.2.53:22"); got != "" {
		t.Fatalf("pin after forget = %q, want empty", got)
	}
}

// TestHostKeyStoreMergeKeepsLocalChanges: out-of-process additions are folded
// in, and an unparsable file fails the save rather than being overwritten.
func TestHostKeyStoreMergeKeepsLocalChanges(t *testing.T) {
	daemon, path := hmTNewStore(t)
	if err := daemon.verify("ssh:192.0.2.60:22", "fp60"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	other := newHostKeyStore(path)
	if err := other.verify("ssh:192.0.2.61:22", "fp61"); err != nil {
		t.Fatalf("other: %v", err)
	}
	if err := daemon.verify("ssh:192.0.2.62:22", "fp62"); err != nil {
		t.Fatalf("daemon: %v", err)
	}
	persisted := hmTReadStore(t, path)
	for _, h := range []string{"ssh:192.0.2.60:22", "ssh:192.0.2.61:22", "ssh:192.0.2.62:22"} {
		if persisted[h] == "" {
			t.Fatalf("%s missing after merge: %v", h, persisted)
		}
	}

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := daemon.verify("ssh:192.0.2.63:22", "fp63"); err == nil {
		t.Fatal("first-use over a corrupt store file must fail closed")
	}
	if data, _ := os.ReadFile(path); string(data) != "not json" {
		t.Fatalf("corrupt store file was overwritten: %q", data)
	}
	// Durable entries still match without touching the file.
	if err := daemon.verify("ssh:192.0.2.60:22", "fp60"); err != nil {
		t.Fatalf("durable match: %v", err)
	}
}

func hmTReadStore(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestHostKeyStoreReadFileOpenError: an open failure other than "not exist"
// (here ENOTDIR from a regular file used as a directory) is a load error.
func TestHostKeyStoreReadFileOpenError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newHostKeyStore(filepath.Join(file, "known_hosts.json"))
	if s.loadErr == nil || !strings.Contains(s.loadErr.Error(), "read host key store") {
		t.Fatalf("loadErr = %v, want read error", s.loadErr)
	}
}

// TestHostKeyStoreRefreshStatError: when the store path becomes unstattable
// for a reason other than absence, refresh logs and reports no change, and a
// save fails rather than writing over an unknown file.
func TestHostKeyStoreRefreshStatError(t *testing.T) {
	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	s := newHostKeyStore(filepath.Join(sub, "known_hosts.json"))
	if s.loadErr != nil {
		t.Fatal(s.loadErr)
	}
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if s.refresh() {
		t.Fatal("refresh reported a change after a stat failure")
	}
	if err := s.persist(true); err == nil || !strings.Contains(err.Error(), "stat host key store") {
		t.Fatalf("persist = %v, want stat error", err)
	}
}

// TestHostKeyStoreMergeTakesOutOfProcessRewrite: an entry rewritten on disk
// by another process replaces the in-memory value this process last saved.
func TestHostKeyStoreMergeTakesOutOfProcessRewrite(t *testing.T) {
	s, path := hmTNewStore(t)
	if err := s.verify("tls:192.0.2.40:443", "fp-old"); err != nil {
		t.Fatal(err)
	}
	// Write via rename so the file identity changes even within mtime
	// granularity.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(`{"tls:192.0.2.40:443":"fp-new-longer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if !s.refresh() {
		t.Fatal("refresh did not report the out-of-process rewrite")
	}
	if err := s.verify("tls:192.0.2.40:443", "fp-new-longer"); err != nil {
		t.Fatalf("verify against rewritten entry: %v", err)
	}
}
