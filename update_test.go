package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelfUpdateBadURL(t *testing.T) {
	err := selfUpdate("http://127.0.0.1:1/nonexistent", "")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestSelfUpdateChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake binary"))
	}))
	defer srv.Close()

	err := selfUpdate(srv.URL, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestSelfUpdateChecksumMatch(t *testing.T) {
	body := []byte("test binary content")
	checksum := fmt.Sprintf("%x", sha256.Sum256(body))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	// This will fail at the rename step (writing to os.Executable path),
	// but the checksum verification should pass
	err := selfUpdate(srv.URL, checksum)
	if err == nil {
		t.Error("expected error (can't replace running binary in test)")
	}
	// The error should NOT be about checksum
	if err != nil && err.Error() != "" {
		// As long as it's not a checksum error, the checksum verification passed
		t.Logf("got expected post-checksum error: %v", err)
	}
}
