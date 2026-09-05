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
	"testing"

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
