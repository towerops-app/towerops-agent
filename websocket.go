// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
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

// phoenixVSNQuery requests the Phoenix serializer V2 transport (binary
// frames) at connect time, before the join. A legacy endpoint that ignores
// the parameter keeps answering the JSON join, and the session falls back to
// V1 frames without knowing the server version ahead of time.
const phoenixVSNQuery = "vsn=2.0.0"

// withVSNQuery appends (or replaces) the Phoenix `vsn` query parameter.
// Existing parameters are preserved so proxies and deployments that already
// carry query arguments keep working.
func withVSNQuery(rawURL string) string {
	if strings.Contains(rawURL, "vsn=") {
		return rawURL
	}
	separator := "?"
	if strings.Contains(rawURL, "?") {
		separator = "&"
	}
	return rawURL + separator + phoenixVSNQuery
}

// wsDial connects to a WebSocket endpoint and completes its opening handshake.
// token, when non-empty, rides the `x-agent-token` upgrade header so a server
// requiring connect-time auth can reject the handshake before any channel
// traffic (issue C7).
func wsDial(ctx context.Context, rawURL string, token ...string) (*wsConn, error) {
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
			recordLocalAddr(localAddr, conn)
		}
		return conn, err
	}

	headers := http.Header{"User-Agent": {"towerops-agent/" + version}}
	if len(token) > 0 && token[0] != "" {
		headers.Set("x-agent-token", token[0])
	}
	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
		HTTPHeader: headers,
		// OID-heavy result payloads share long prefixes, so permessage-deflate
		// with context takeover meaningfully shrinks the uplink. The server
		// may negotiate no-context-takeover or disable the extension; the
		// library falls back transparently, and a legacy server that never
		// offered the extension runs uncompressed.
		CompressionMode: websocket.CompressionContextTakeover,
	}
	conn, response, err := websocket.Dial(ctx, withVSNQuery(rawURL), opts)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dial websocket: %w", err)
	}
	conn.SetReadLimit(int64(maxMessageSize))
	return &wsConn{conn: conn, localAddr: lastLocalAddr(localAddr)}, nil
}

// recordLocalAddr stores the dialed socket's local address for LocalIP. The
// non-blocking send keeps a retried dial from stalling when an earlier
// attempt already recorded its address.
func recordLocalAddr(ch chan<- string, conn net.Conn) {
	select {
	case ch <- conn.LocalAddr().String():
	default:
	}
}

// lastLocalAddr drains the recorded dial address, returning "" when no
// attempt reported one.
func lastLocalAddr(ch <-chan string) string {
	select {
	case addr := <-ch:
		return addr
	default:
		return ""
	}
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

// ReadMessage reads one complete text or binary message. Phoenix serializer
// V2 requires the caller to dispatch on this kind rather than sniffing bytes.
func (ws *wsConn) ReadMessage(ctx context.Context) (websocket.MessageType, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wsReadTimeout)
	defer cancel()

	return ws.conn.Read(ctx)
}

// WriteText writes one text message.
func (ws *wsConn) WriteText(ctx context.Context, data []byte) error {
	return ws.write(ctx, data, websocket.MessageText)
}

// WriteBinary writes one binary message (Phoenix serializer V2 frame).
func (ws *wsConn) WriteBinary(ctx context.Context, data []byte) error {
	return ws.write(ctx, data, websocket.MessageBinary)
}

func (ws *wsConn) write(ctx context.Context, data []byte, kind websocket.MessageType) error {
	ctx, cancel := context.WithTimeout(ctx, wsWriteTimeoutFor(len(data)))
	defer cancel()
	return ws.conn.Write(ctx, kind, data)
}

// Close immediately releases the connection and unblocks pending I/O. Session
// shutdown must not wait for a peer that may already be unreachable.
func (ws *wsConn) Close() error {
	return ws.conn.CloseNow()
}
