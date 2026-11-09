// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWSDialReadWriteAndClose(t *testing.T) {
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()

		messageType, data, err := conn.Read(r.Context())
		if err == nil {
			err = conn.Write(r.Context(), messageType, data)
		}
		serverErr <- err
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	want := []byte("hello")
	if err := ws.WriteText(context.Background(), want); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	got, err := ws.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ReadMessage = %q, want %q", got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestWSDialSendsUserAgent(t *testing.T) {
	userAgent := make(chan string, 1)
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent <- r.Header.Get("User-Agent")
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		serverErr <- conn.CloseNow()
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	if got, want := <-userAgent, "towerops-agent/"+version; got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestWSConnLocalIP(t *testing.T) {
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		serverErr <- conn.CloseNow()
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	got := ws.LocalIP()
	if net.ParseIP(got) == nil {
		t.Errorf("LocalIP() = %q, want a valid IP address", got)
	}
	if got != "127.0.0.1" {
		t.Errorf("LocalIP() = %q, want 127.0.0.1", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestWSConnLocalIPUnparsableAddress(t *testing.T) {
	tests := []struct {
		name      string
		localAddr string
	}{
		{name: "transport reported nothing", localAddr: ""},
		{name: "address without a port", localAddr: "192.0.2.10"},
		{name: "address with too many colons", localAddr: "::1:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := &wsConn{localAddr: tt.localAddr}
			if got := ws.LocalIP(); got != "" {
				t.Errorf("LocalIP() = %q, want %q", got, "")
			}
		})
	}
}

func TestWSDialRejectsNonWebSocketURL(t *testing.T) {
	if _, err := wsDial(context.Background(), "ftp://example.com/socket"); err == nil {
		t.Fatal("wsDial accepted an ftp URL")
	}
}

// TestWSDialClosesResponseBodyOnFailedHandshake drives the branch where
// websocket.Dial returns a non-nil *http.Response alongside an error, which
// happens when a real HTTP server answers the upgrade with a non-101 status.
func TestWSDialClosesResponseBodyOnFailedHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err == nil {
		_ = ws.Close()
		t.Fatal("wsDial succeeded against a 404 handler")
	}
	if ws != nil {
		t.Errorf("wsDial conn = %v, want nil on handshake failure", ws)
	}
	if !strings.Contains(err.Error(), "dial websocket") {
		t.Errorf("wsDial error = %v, want it wrapped with \"dial websocket\"", err)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("wsDial error = %v, want the 404 status surfaced", err)
	}
}

func TestWSConnReadLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		_ = conn.Write(context.Background(), websocket.MessageBinary, make([]byte, maxMessageSize+1))
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	_, err = ws.ReadMessage(context.Background())
	if !errors.Is(err, websocket.ErrMessageTooBig) {
		t.Fatalf("ReadMessage error = %v, want ErrMessageTooBig", err)
	}
}

// TestWSWriteTimeoutForScalesWithSize pins the write-deadline floor for small
// frames and the size scaling at the 1Mbps floor rate that keeps multi-MiB
// results from timing out on slow uplinks.
func TestWSWriteTimeoutForScalesWithSize(t *testing.T) {
	tests := []struct {
		name string
		size int
		want time.Duration
	}{
		{"zero", 0, wsWriteTimeout},
		{"small control frame", 256, wsWriteTimeout},
		{"below threshold", wsSmallMessageSize - 1, wsWriteTimeout},
		{"at threshold", wsSmallMessageSize, wsWriteTimeout},
		{"just over threshold", wsSmallMessageSize + 1, wsWriteTimeout + (wsSmallMessageSize+1)*time.Second/wsMinWriteBytesPerSec},
		{"8MiB result at 4Mbps needs ~28s plus margin", 8 << 20, wsWriteTimeout + 8388608*time.Second/wsMinWriteBytesPerSec},
		{"max encoded payload", 14 << 20, wsWriteTimeout + 14680064*time.Second/wsMinWriteBytesPerSec},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wsWriteTimeoutFor(tt.size); got != tt.want {
				t.Errorf("wsWriteTimeoutFor(%d) = %v, want %v", tt.size, got, tt.want)
			}
		})
	}

	if wsWriteTimeoutFor(8<<20) <= wsWriteTimeoutFor(8<<20-1) {
		t.Error("write timeout is not strictly increasing in size")
	}
}

// The read limit must sit above the largest payload decodeBinaryPayload can
// see: a frame it could still refuse must reach it, because the refusal is
// what tells the server not to push that inventory again. A frame killed by
// the read limit tears the session down with no rejection at all.
func TestWSReadLimitAdmitsRefusablePayloads(t *testing.T) {
	if maxMessageSize <= maxEncodedJobPayloadBytes {
		t.Fatalf("maxMessageSize = %d, must sit above maxEncodedJobPayloadBytes %d",
			maxMessageSize, maxEncodedJobPayloadBytes)
	}

	// Just above the decode cap, well below the read limit: delivered.
	oversize := make([]byte, maxEncodedJobPayloadBytes+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		_ = conn.Write(r.Context(), websocket.MessageBinary, oversize)
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	data, err := ws.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("frame above the decode cap was killed by the read limit: %v", err)
	}
	if len(data) != len(oversize) {
		t.Fatalf("delivered %d bytes, want %d", len(data), len(oversize))
	}
}

// A failed handshake must not leave its connection parked in the discarded
// transport's idle pool: the socket and its two goroutines would hold on
// until the 90s idle timeout on every failed dial.
func TestFailedHandshakeReleasesIdleConnection(t *testing.T) {
	var active atomic.Int32
	done := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateActive:
			active.Add(1)
		case http.StateClosed, http.StateHijacked, http.StateIdle:
			if active.Add(-1) == 0 {
				select {
				case <-done:
				default:
					close(done)
				}
			}
		}
	}
	srv.Start()
	defer srv.Close()

	if _, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http")); err == nil {
		t.Fatal("wsDial succeeded against a 403 handler")
	}

	// Without the fix the connection sits idle client-side and the server
	// never sees it close; with the fix this returns in milliseconds.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("failed handshake left %d server-side connections open", active.Load())
	}
}
