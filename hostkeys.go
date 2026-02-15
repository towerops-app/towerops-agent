package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

// hostKeyStore implements trust-on-first-use (TOFU) for SSH host keys and TLS cert fingerprints.
type hostKeyStore struct {
	path string
	mu   sync.Mutex
	keys map[string]string // "host:port" -> hex fingerprint
}

var globalHostKeys *hostKeyStore
var hostKeysOnce sync.Once

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
		_ = json.Unmarshal(data, &s.keys)
	}
	return s
}

func (s *hostKeyStore) save() error {
	data, err := json.MarshalIndent(s.keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// verify checks a fingerprint for host. Returns nil on match or first-use, error on mismatch.
func (s *hostKeyStore) verify(host, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.keys[host]
	if !exists {
		slog.Warn("TOFU: first connection, trusting host key", "host", host, "fingerprint", fingerprint)
		s.keys[host] = fingerprint
		if err := s.save(); err != nil {
			slog.Error("failed to save host keys", "error", err)
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
