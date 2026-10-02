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
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const defaultHostKeysPath = "./known_hosts.json"

// hostKeyStore implements trust-on-first-use (TOFU) for SSH host keys and TLS
// cert fingerprints. Lookups and map mutation run under mu; the durable write
// (marshal, fsync, rename) runs under saveMu so a sweep of new devices does
// not serialize every SSH/TLS dial behind each other's fsyncs. gen counts map
// mutations and savedGen records the newest mutation a completed save covered,
// letting callers fail closed without trusting entries that are not durable.
type hostKeyStore struct {
	path     string
	mu       sync.Mutex
	saveMu   sync.Mutex
	keys     map[string]string // namespaced endpoint -> storedHostKeyEntry value
	gen      uint64            // bumped on every map mutation; guarded by mu
	savedGen uint64            // newest gen persisted by a completed save; guarded by mu
	loadErr  error
}

var globalHostKeys *hostKeyStore

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

// initHostKeyStore installs the process-wide TOFU store, failing startup when
// the path is unreadable or unwritable instead of the first SSH job.
func initHostKeyStore(path string) error {
	s := newHostKeyStore(path)
	if s.loadErr != nil {
		return s.loadErr
	}
	if err := s.save(); err != nil {
		return fmt.Errorf("host key store %s: %w", path, err)
	}
	globalHostKeys = s
	return nil
}

// getHostKeyStore returns the store installed by initHostKeyStore, which
// runMain calls before any job can reach an SSH or TLS endpoint.
func getHostKeyStore() *hostKeyStore {
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

// save persists the map under saveMu, serializing callers while keeping mu
// free for lookups: the marshal snapshots under a brief mu hold, then the
// fsync+rename runs under saveMu only. On success savedGen advances to the
// snapshotted generation. Callers holding mu must never call save directly —
// save takes mu itself, so that would deadlock.
func (s *hostKeyStore) save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	gen := s.gen
	data, err := hostKeyMarshal(s.keys, "", "  ")
	s.mu.Unlock()
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
	if err := syncDirectory(dir); err != nil {
		return err
	}
	s.mu.Lock()
	if gen > s.savedGen {
		s.savedGen = gen
	}
	s.mu.Unlock()
	return nil
}

// verify checks a fingerprint for host. Returns nil on match or first-use, error on mismatch.
// Entries written through this path stay untyped; see verifySSHKey for the
// typed SSH entries that pin HostKeyAlgorithms.
func (s *hostKeyStore) verify(host, fingerprint string) error {
	return s.verifyKey(host, fingerprint, "")
}

// verifySSHKey checks an SSH public key against the store under the "ssh:"
// namespace, persisting it typed so pinnedKeyAlgorithm can restrict later
// connections to the same key algorithm.
func (s *hostKeyStore) verifySSHKey(host string, key ssh.PublicKey) error {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
	return s.verifyKey(host, fingerprint, key.Type())
}

// storedHostKeyEntry renders a store value: a bare fingerprint for untyped
// entries, or "<key type> <fingerprint>" for SSH keys so the pinned key's
// algorithm survives a restart.
func storedHostKeyEntry(fingerprint, keyType string) string {
	if keyType == "" {
		return fingerprint
	}
	return keyType + " " + fingerprint
}

// splitHostKeyEntry parses a store value into key type and fingerprint. A
// value with no space is an untyped entry written by an older release.
func splitHostKeyEntry(value string) (keyType, fingerprint string) {
	if before, after, ok := strings.Cut(value, " "); ok {
		return before, after
	}
	return "", value
}

func (s *hostKeyStore) verifyKey(host, fingerprint, keyType string) error {
	// A first-use trust and a later match that only confirmed an unsaved
	// mutation both need the map durable before the connection proceeds;
	// retry re-locks and re-checks after each save so a concurrent rollback
	// cannot slip a never-persisted entry past a successful save.
	for {
		s.mu.Lock()
		if s.loadErr != nil {
			err := s.loadErr
			s.mu.Unlock()
			return err
		}

		stored, exists := s.keys[host]
		legacyHost := ""
		if !exists {
			if candidate, ok := strings.CutPrefix(host, "ssh:"); ok {
				stored, exists = s.keys[candidate]
				if exists {
					legacyHost = candidate
				}
			}
		}
		entry := storedHostKeyEntry(fingerprint, keyType)
		if !exists {
			slog.Warn("TOFU: first connection, trusting host key", "host", host, "fingerprint", fingerprint)
			s.keys[host] = entry
			s.gen++
			gen := s.gen
			s.mu.Unlock()
			err := s.save()
			if err != nil {
				s.mu.Lock()
				if s.savedGen >= gen {
					// A concurrent save already wrote this generation.
					s.mu.Unlock()
					return nil
				}
				delete(s.keys, host)
				s.mu.Unlock()
				return fmt.Errorf("failed to persist trusted host key for %s: %w", host, err)
			}
			continue
		}

		if _, storedFingerprint := splitHostKeyEntry(stored); storedFingerprint != fingerprint {
			s.mu.Unlock()
			return fmt.Errorf("TOFU: host key changed for %s (stored=%s, got=%s) - possible MITM", host, storedFingerprint, fingerprint)
		}

		// Migrate a matching entry in one save when it is stored under the
		// legacy un-namespaced key or was written by an older release without
		// the key type.
		if legacyHost != "" || stored != entry {
			if legacyHost != "" {
				delete(s.keys, legacyHost)
			}
			s.keys[host] = entry
			s.gen++
			gen := s.gen
			s.mu.Unlock()
			err := s.save()
			if err != nil {
				s.mu.Lock()
				if s.savedGen >= gen {
					s.mu.Unlock()
					return nil
				}
				if legacyHost == "" {
					s.keys[host] = stored
				} else {
					delete(s.keys, host)
					s.keys[legacyHost] = stored
				}
				s.mu.Unlock()
				slog.Warn("failed to migrate trusted host key; continuing with verified legacy entry",
					"legacy_host", legacyHost, "host", host, "error", err)
				return nil
			}
			continue
		}

		if s.savedGen >= s.gen {
			s.mu.Unlock()
			return nil
		}
		// A first-use or migration is mid-save; fail closed by persisting
		// before trusting the match.
		s.mu.Unlock()
		if err := s.save(); err != nil {
			return err
		}
	}
}

// forget removes the entries for host from the store and persists the change.
// host may be given as "ip:port", which removes the "ssh:"/"tls:" entries and
// any legacy un-namespaced entry, or verbatim ("ssh:ip:port", "tls:ip:port").
// It reports whether anything was removed.
func (s *hostKeyStore) forget(host string) (bool, error) {
	s.mu.Lock()
	if s.loadErr != nil {
		err := s.loadErr
		s.mu.Unlock()
		return false, err
	}

	candidates := []string{host, "ssh:" + host, "tls:" + host}
	var removed map[string]string
	for _, key := range candidates {
		if stored, ok := s.keys[key]; ok {
			if removed == nil {
				removed = make(map[string]string, len(candidates))
			}
			removed[key] = stored
			delete(s.keys, key)
		}
	}
	if len(removed) == 0 {
		s.mu.Unlock()
		return false, nil
	}
	s.gen++
	gen := s.gen
	s.mu.Unlock()

	if err := s.save(); err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.savedGen >= gen {
			// A concurrent save already wrote the deletion; the map already
			// reflects it, so the request is complete.
			return true, nil
		}
		for key, stored := range removed {
			s.keys[key] = stored
		}
		return false, fmt.Errorf("failed to persist host key removal for %s: %w", host, err)
	}
	return true, nil
}

// pinnedKeyAlgorithm returns the key type recorded for an ssh: host entry, or
// "" when no typed entry exists, so callers can pin HostKeyAlgorithms.
func (s *hostKeyStore) pinnedKeyAlgorithm(host string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return ""
	}
	if stored, ok := s.keys[host]; ok {
		if keyType, _ := splitHostKeyEntry(stored); keyType != "" {
			return keyType
		}
	}
	return ""
}

// sshHostKeyCallback returns an ssh.HostKeyCallback that uses TOFU verification.
func sshHostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return getHostKeyStore().verifySSHKey("ssh:"+remote.String(), key)
	}
}

// tlsCertFingerprint returns the SHA-256 hex fingerprint of a DER-encoded certificate.
func tlsCertFingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
}
