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
	"maps"
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
// mutations and savedGen records the newest mutation a completed save covered.
// pending maps each entry trusted or rewritten since the last save to the
// generation that wrote it, so a match fails closed only on an entry that is
// not yet durable and never touches disk for one that already is.
//
// The file may also be edited out of process (--forget-host-key). base and
// diskInfo record the file contents and identity this process last read or
// wrote; before every write, and before rejecting a mismatched key or pinning
// an algorithm, a changed file is three-way merged into keys so removals made
// on disk are kept instead of being resurrected by the next save.
type hostKeyStore struct {
	path     string
	mu       sync.Mutex
	saveMu   sync.Mutex
	keys     map[string]string // namespaced endpoint -> storedHostKeyEntry value
	pending  map[string]uint64 // entry -> gen of its unsaved write; guarded by mu
	gen      uint64            // bumped on every map mutation; guarded by mu
	savedGen uint64            // newest gen persisted by a completed save; guarded by mu
	base     map[string]string // file contents last read or written; guarded by saveMu
	diskInfo os.FileInfo       // identity of the file base came from; guarded by saveMu
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
	if err := s.persist(true); err != nil {
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
	s := &hostKeyStore{path: path, keys: make(map[string]string), pending: make(map[string]uint64)}
	keys, info, err := readHostKeyFile(path)
	if err != nil {
		s.loadErr = err
		return s
	}
	if keys != nil {
		s.keys = keys
		s.base = maps.Clone(keys)
		s.diskInfo = info
	}
	return s
}

// readHostKeyFile reads and parses the store file, returning the stat of the
// same open file so a later rename by another process is detectable. A
// missing file yields nil keys and no error.
func readHostKeyFile(path string) (map[string]string, os.FileInfo, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read host key store %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("read host key store %s: %w", path, err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("read host key store %s: %w", path, err)
	}
	keys := make(map[string]string)
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, nil, fmt.Errorf("parse host key store %s: %w", path, err)
	}
	return keys, info, nil
}

// sameHostKeyFile reports whether two stats describe the same unmodified
// file. Every save renames a fresh inode into place, so a write by another
// process changes the identity even when size and mtime happen to match.
func sameHostKeyFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// mergeDiskLocked folds out-of-process edits into keys when the file changed
// since this process last read or wrote it. Entries the file changed or
// removed relative to base take the file's version; entries the file added
// are kept unless this process wrote the same key since. A missing file is
// left alone so the next write recreates it. Callers hold saveMu, not mu.
func (s *hostKeyStore) mergeDiskLocked() (bool, error) {
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat host key store %s: %w", s.path, err)
	}
	if !info.Mode().IsRegular() || (s.diskInfo != nil && sameHostKeyFile(s.diskInfo, info)) {
		// Nothing to merge from a non-file; the write reports the problem.
		return false, nil
	}
	disk, info, err := readHostKeyFile(s.path)
	if err != nil || disk == nil {
		return false, err
	}

	s.mu.Lock()
	for key, was := range s.base {
		now, ok := disk[key]
		if ok && now == was {
			continue
		}
		delete(s.pending, key)
		if ok {
			s.keys[key] = now
		} else {
			delete(s.keys, key)
		}
	}
	for key, value := range disk {
		if _, inBase := s.base[key]; inBase {
			continue
		}
		if _, inMem := s.keys[key]; !inMem {
			s.keys[key] = value
		}
	}
	s.mu.Unlock()
	s.base, s.diskInfo = disk, info
	return true, nil
}

// refresh merges out-of-process edits without writing. It skips when a save
// is in flight rather than wait behind its fsync; that save merges the file
// itself. It reports whether the map may have changed.
func (s *hostKeyStore) refresh() bool {
	if !s.saveMu.TryLock() {
		return false
	}
	defer s.saveMu.Unlock()
	s.mu.Lock()
	broken := s.loadErr != nil
	s.mu.Unlock()
	if broken {
		return false
	}
	changed, err := s.mergeDiskLocked()
	if err != nil {
		slog.Warn("failed to reload host key store", "path", s.path, "error", err)
	}
	return changed
}

// save persists the map under saveMu, serializing callers while keeping mu
// free for lookups. A caller whose mutation another save already covered
// returns without writing again.
func (s *hostKeyStore) save() error {
	return s.persist(false)
}

// persist merges out-of-process edits, then writes the map unless force is
// false and nothing is unsaved. The marshal snapshots under a brief mu hold
// and the fsync+rename runs under saveMu only. On success savedGen advances
// to the snapshotted generation. Callers holding mu must never call persist —
// it takes mu itself, so that would deadlock.
func (s *hostKeyStore) persist(force bool) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	if _, err := s.mergeDiskLocked(); err != nil {
		return err
	}
	s.mu.Lock()
	if !force && s.savedGen >= s.gen {
		s.mu.Unlock()
		return nil
	}
	gen := s.gen
	snapshot := maps.Clone(s.keys)
	s.mu.Unlock()
	data, err := hostKeyMarshal(snapshot, "", "  ")
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
	// Stat the temp file before the rename so the recorded identity is our
	// own write, not a racing out-of-process one renamed over it.
	info, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return err
	}
	s.base, s.diskInfo = snapshot, info
	if err := syncDirectory(dir); err != nil {
		return err
	}
	s.mu.Lock()
	if gen > s.savedGen {
		s.savedGen = gen
	}
	for key, g := range s.pending {
		if g <= gen {
			delete(s.pending, key)
		}
	}
	s.mu.Unlock()
	return nil
}

// markPending records host as written by gen and not yet durable. Callers
// hold mu.
func (s *hostKeyStore) markPending(host string, gen uint64) {
	if s.pending == nil {
		s.pending = make(map[string]uint64)
	}
	s.pending[host] = gen
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
	refreshed := false
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
			s.markPending(host, gen)
			s.mu.Unlock()
			err := s.save()
			if err != nil {
				s.mu.Lock()
				if s.savedGen >= gen {
					// A concurrent save already wrote this generation.
					s.mu.Unlock()
					return nil
				}
				// Only this entry is rolled back; gen is not, but pending
				// keeps matches on already-durable entries off the disk.
				delete(s.keys, host)
				if s.pending[host] == gen {
					delete(s.pending, host)
				}
				s.mu.Unlock()
				return fmt.Errorf("failed to persist trusted host key for %s: %w", host, err)
			}
			continue
		}

		if _, storedFingerprint := splitHostKeyEntry(stored); storedFingerprint != fingerprint {
			s.mu.Unlock()
			// The entry may have been removed out of process with
			// --forget-host-key; re-read a changed file once before failing.
			if !refreshed {
				refreshed = true
				if s.refresh() {
					continue
				}
			}
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
			s.markPending(host, gen)
			s.mu.Unlock()
			err := s.save()
			if err != nil {
				s.mu.Lock()
				if s.savedGen >= gen {
					s.mu.Unlock()
					return nil
				}
				// The restored entry is the one already on disk.
				if s.pending[host] == gen {
					delete(s.pending, host)
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

		if g, ok := s.pending[host]; !ok || s.savedGen >= g {
			s.mu.Unlock()
			return nil
		}
		// This entry's first-use or migration is mid-save; fail closed by
		// persisting before trusting the match.
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
	// Pick up an out-of-process --forget-host-key first: a stale pin would
	// fail the handshake on algorithm negotiation before the host key
	// callback could notice the removal.
	s.refresh()
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
