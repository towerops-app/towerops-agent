// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/coder/websocket"
)

const (
	wsHandshakeTimeout = 30 * time.Second
	wsReadTimeout      = 90 * time.Second
	wsWriteTimeout     = 30 * time.Second
	maxMessageSize     = 16 << 20
)

// wsConn keeps the small interface used by the agent while delegating the
// WebSocket protocol to coder/websocket.
type wsConn struct {
	conn *websocket.Conn
}

// wsDial connects to a WebSocket endpoint and completes its opening handshake.
func wsDial(ctx context.Context, rawURL string) (*wsConn, error) {
	ctx, cancel := context.WithTimeout(ctx, wsHandshakeTimeout)
	defer cancel()

	conn, response, err := websocket.Dial(ctx, rawURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dial websocket: %w", err)
	}
	conn.SetReadLimit(maxMessageSize)
	return &wsConn{conn: conn}, nil
}

// ReadMessage reads one complete text or binary message.
func (ws *wsConn) ReadMessage(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wsReadTimeout)
	defer cancel()

	_, data, err := ws.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteText writes one text message.
func (ws *wsConn) WriteText(ctx context.Context, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
	defer cancel()
	return ws.conn.Write(ctx, websocket.MessageText, data)
}

// Close immediately releases the connection and unblocks pending I/O. Session
// shutdown must not wait for a peer that may already be unreachable.
func (ws *wsConn) Close() error {
	return ws.conn.CloseNow()
}
