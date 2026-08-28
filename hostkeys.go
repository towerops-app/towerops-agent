// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

// hostKeyStore implements trust-on-first-use (TOFU) for SSH host keys and TLS cert fingerprints.
type hostKeyStore struct {
	path    string
	mu      sync.Mutex
	keys    map[string]string // "host:port" -> hex fingerprint
	loadErr error
}

var globalHostKeys *hostKeyStore
var hostKeysOnce sync.Once

// hostKeyTempFile is the subset of *os.File that save uses. Together with the
// hostKeyCreateTemp and hostKeyMarshal seams it lets tests exercise the
// serialization and durable-write failure paths that cannot be provoked
// through the filesystem.
type hostKeyTempFile interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

var hostKeyMarshal = json.MarshalIndent
var hostKeyCreateTemp = func(dir, pattern string) (hostKeyTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

func getHostKeyStore() *hostKeyStore {
	hostKeysOnce.Do(func() {
		path := os.Getenv("TOWEROPS_HOST_KEYS_FILE")
		if path == "" {
			path = "./known_hosts.json"
		}
		globalHostKeys = newHostKeyStore(path)
	})
	return globalHostKeys
}

func newHostKeyStore(path string) *hostKeyStore {
	s := &hostKeyStore{path: path, keys: make(map[string]string)}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.keys); err != nil {
			s.loadErr = fmt.Errorf("parse host key store %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		s.loadErr = fmt.Errorf("read host key store %s: %w", path, err)
	}
	return s
}

func (s *hostKeyStore) save() error {
	data, err := hostKeyMarshal(s.keys, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := hostKeyCreateTemp(dir, "."+filepath.Base(s.path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := writeAll(tmp, data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

// verify checks a fingerprint for host. Returns nil on match or first-use, error on mismatch.
func (s *hostKeyStore) verify(host, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}

	stored, exists := s.keys[host]
	if !exists {
		slog.Warn("TOFU: first connection, trusting host key", "host", host, "fingerprint", fingerprint)
		s.keys[host] = fingerprint
		if err := s.save(); err != nil {
			delete(s.keys, host)
			return fmt.Errorf("failed to persist trusted host key for %s: %w", host, err)
		}
		return nil
	}

	if stored != fingerprint {
		return fmt.Errorf("TOFU: host key changed for %s (stored=%s, got=%s) — possible MITM", host, stored, fingerprint)
	}
	return nil
}

// sshHostKeyCallback returns an ssh.HostKeyCallback that uses TOFU verification.
func sshHostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
		store := getHostKeyStore()
		return store.verify(remote.String(), fingerprint)
	}
}

// tlsCertFingerprint returns the SHA-256 hex fingerprint of a DER-encoded certificate.
func tlsCertFingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
}
