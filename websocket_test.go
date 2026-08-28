// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
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

	ws, err := WSDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("WSDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	want := []byte("hello")
	if err := ws.WriteText(context.Background(), want); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	got, messageType, err := ws.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if messageType != int(websocket.MessageText) || string(got) != string(want) {
		t.Fatalf("ReadMessage = (%d, %q), want (%d, %q)", messageType, got, websocket.MessageText, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestWSDialRejectsNonWebSocketURL(t *testing.T) {
	if _, err := WSDial(context.Background(), "ftp://example.com/socket"); err == nil {
		t.Fatal("WSDial accepted an ftp URL")
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

	ws, err := WSDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("WSDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	_, _, err = ws.ReadMessage(context.Background())
	if !errors.Is(err, websocket.ErrMessageTooBig) {
		t.Fatalf("ReadMessage error = %v, want ErrMessageTooBig", err)
	}
}
