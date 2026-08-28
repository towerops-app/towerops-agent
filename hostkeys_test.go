// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
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

func TestGetHostKeyStoreDefault(t *testing.T) {
	// Reset the once for testing
	origStore := globalHostKeys
	defer func() {
		hostKeysOnce = sync.Once{}
		globalHostKeys = origStore
	}()
	hostKeysOnce = sync.Once{}

	t.Setenv("TOWEROPS_HOST_KEYS_FILE", filepath.Join(t.TempDir(), "test_hosts.json"))
	store := getHostKeyStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestSSHHostKeyCallback(t *testing.T) {
	// Reset global state
	origStore := globalHostKeys
	defer func() {
		hostKeysOnce = sync.Once{}
		globalHostKeys = origStore
	}()
	hostKeysOnce = sync.Once{}
	t.Setenv("TOWEROPS_HOST_KEYS_FILE", filepath.Join(t.TempDir(), "hosts.json"))

	cb := sshHostKeyCallback()
	if cb == nil {
		t.Fatal("expected non-nil callback")
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
