// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

const (
	wsHandshakeTimeout = 30 * time.Second
	wsReadTimeout      = 90 * time.Second
	wsWriteTimeout     = 30 * time.Second
)

// wsMaxReadOverhead bounds the JSON envelope (topic, event, ref and the
// "binary" key) that wraps an encoded payload, on top of the payload itself.
const wsMaxReadOverhead = 1 << 20

// maxMessageSize caps inbound frames just above the largest payload the agent
// can decode and refuse. decodeBinaryPayload rejects encoded payloads over
// maxEncodedJobPayloadBytes with an inventory_rejection notice the server
// needs to re-push the inventory, so the read limit must sit above that: a
// frame killed by the read limit tears the session down before any rejection
// can be sent, and every session would die right after joining.
var maxMessageSize = maxEncodedJobPayloadBytes + wsMaxReadOverhead

// wsMinWriteBytesPerSec is the assumed uplink floor (1 Mbps) used to scale the
// write deadline. The fixed wsWriteTimeout alone lets an ~8MiB base64 result
// exhaust 30s on a ~4Mbps link and tear down a healthy session on every
// retry, so large frames get extra time instead.
const wsMinWriteBytesPerSec = 125_000

// wsSmallMessageSize bounds frames small enough that wsWriteTimeout still
// covers them even at the floor rate; below it the deadline is unchanged.
const wsSmallMessageSize = 1 << 20

// wsWriteTimeoutFor returns the write deadline for a frame of size bytes.
// Small frames keep the fixed wsWriteTimeout; larger ones get the extra time
// needed to push the payload at the floor rate.
func wsWriteTimeoutFor(size int) time.Duration {
	if size <= wsSmallMessageSize {
		return wsWriteTimeout
	}
	return wsWriteTimeout + time.Duration(size)*time.Second/wsMinWriteBytesPerSec
}

// wsConn keeps the small interface used by the agent while delegating the
// WebSocket protocol to coder/websocket.
type wsConn struct {
	conn      *websocket.Conn
	localAddr string
}

// wsDial connects to a WebSocket endpoint and completes its opening handshake.
func wsDial(ctx context.Context, rawURL string) (*wsConn, error) {
	ctx, cancel := context.WithTimeout(ctx, wsHandshakeTimeout)
	defer cancel()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The client serves this handshake only and is never stored: a failed
	// handshake (403/502) returns its connection to the clone's idle pool,
	// where it would hold a socket and two goroutines for the 90s idle
	// timeout per failed dial. Closing idle connections when the dial ends
	// releases them; the upgraded connection of a successful handshake is
	// handed to coder/websocket as an in-use response body, not an idle
	// pooled connection, so this cannot disturb a live session.
	defer transport.CloseIdleConnections()
	dialContext := transport.DialContext
	localAddr := make(chan string, 1)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, address)
		if err == nil {
			select {
			case localAddr <- conn.LocalAddr().String():
			default:
			}
		}
		return conn, err
	}

	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
		HTTPHeader: http.Header{"User-Agent": {"towerops-agent/" + version}},
	}
	conn, response, err := websocket.Dial(ctx, rawURL, opts)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dial websocket: %w", err)
	}
	conn.SetReadLimit(int64(maxMessageSize))
	var recordedAddr string
	select {
	case recordedAddr = <-localAddr:
	default:
	}
	return &wsConn{conn: conn, localAddr: recordedAddr}, nil
}

// LocalIP returns the local address of the underlying TCP connection without
// its port, or "" when the transport did not report one.
func (ws *wsConn) LocalIP() string {
	host, _, err := net.SplitHostPort(ws.localAddr)
	if err != nil {
		return ""
	}
	return host
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
	ctx, cancel := context.WithTimeout(ctx, wsWriteTimeoutFor(len(data)))
	defer cancel()
	return ws.conn.Write(ctx, websocket.MessageText, data)
}

// Close immediately releases the connection and unblocks pending I/O. Session
// shutdown must not wait for a peer that may already be unreachable.
func (ws *wsConn) Close() error {
	return ws.conn.CloseNow()
}
