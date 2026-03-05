package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// websocketGUID is the magic GUID from RFC 6455 Section 4.2.2.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// computeAcceptKey computes the expected Sec-WebSocket-Accept value per RFC 6455.
func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

const (
	opText   = 1
	opBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10

	maxFrameSize = 16 << 20 // 16 MB
)

// WSConn is a minimal RFC 6455 WebSocket client.
type WSConn struct {
	conn   io.ReadWriteCloser
	reader *bufio.Reader
	mu     sync.Mutex // serializes writes
}

var wsHandshakeTimeout = 30 * time.Second

var randRead = rand.Read
var netDial = net.Dial
var tlsDial = func(network, addr string) (net.Conn, error) {
	return tls.Dial(network, addr, &tls.Config{MinVersion: tls.VersionTLS12})
}

// WSDial connects to a WebSocket endpoint and performs the HTTP upgrade handshake.
// If the initial connection attempt fails (e.g. server returns 403 over IPv6),
// it retries with IPv4 only.
func WSDial(rawURL string) (*WSConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	ws, err := wsConnect(u, host, "tcp")
	if err != nil {
		slog.Warn("connection failed, retrying with IPv4", "error", err)
		ws, err4 := wsConnect(u, host, "tcp4")
		if err4 != nil {
			return nil, err // return original error
		}
		return ws, nil
	}
	return ws, nil
}

// wsConnect dials the host using the given network ("tcp", "tcp4", "tcp6")
// and performs the WebSocket upgrade handshake.
func wsConnect(u *url.URL, host, network string) (*WSConn, error) {
	useTLS := u.Scheme == "wss"

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tlsDial(network, host)
	} else {
		conn, err = netDial(network, host)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	// Set handshake deadline — prevents a slow/malicious server from blocking indefinitely
	_ = conn.SetDeadline(time.Now().Add(wsHandshakeTimeout))

	// Generate random key for Sec-WebSocket-Key
	keyBytes := make([]byte, 16)
	if _, err := randRead(keyBytes); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key)

	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write handshake: %w", err)
	}

	// Read HTTP response headers using a buffered reader.
	// A single conn.Read may not capture the full response if it spans
	// multiple TCP segments, so we read line by line until the blank line.
	br := bufio.NewReaderSize(conn, 4096)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake failed: %s", strings.TrimSpace(statusLine))
	}

	// Read remaining headers, verify Sec-WebSocket-Accept per RFC 6455
	expectedAccept := computeAcceptKey(key)
	acceptFound := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read handshake headers: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break // end of headers
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept: ") {
			actual := strings.TrimSpace(line[len("Sec-WebSocket-Accept: "):])
			if actual != expectedAccept {
				_ = conn.Close()
				return nil, fmt.Errorf("invalid accept key: got %q, want %q", actual, expectedAccept)
			}
			acceptFound = true
		}
	}
	if !acceptFound {
		_ = conn.Close()
		return nil, fmt.Errorf("missing Sec-WebSocket-Accept header")
	}

	// Clear handshake deadline — normal operation uses no deadline
	_ = conn.SetDeadline(time.Time{})

	// Reuse the buffered reader — it may hold leftover data from the handshake
	return &WSConn{conn: conn, reader: br}, nil
}

// ReadMessage reads the next text or binary message, handling control frames internally.
func (ws *WSConn) ReadMessage() ([]byte, int, error) {
	for {
		opcode, payload, err := ws.readFrame()
		if err != nil {
			return nil, 0, err
		}
		switch opcode {
		case opText, opBinary:
			return payload, opcode, nil
		case opPing:
			if err := ws.writeFrame(opPong, payload); err != nil {
				return nil, 0, fmt.Errorf("pong: %w", err)
			}
		case opClose:
			_ = ws.writeFrame(opClose, nil) // best-effort close reply
			return nil, opClose, io.EOF
		}
	}
}

// WriteText sends a masked text frame.
func (ws *WSConn) WriteText(data []byte) error {
	return ws.writeFrame(opText, data)
}

// Close sends a close frame and closes the underlying connection.
func (ws *WSConn) Close() error {
	_ = ws.writeFrame(opClose, nil) // best-effort
	return ws.conn.Close()
}

const wsReadTimeout = 90 * time.Second
const wsWriteTimeout = 30 * time.Second

func (ws *WSConn) readFrame() (opcode int, payload []byte, err error) {
	// Set read deadline to detect dead connections (MEDIUM-4)
	if nc, ok := ws.conn.(net.Conn); ok {
		_ = nc.SetReadDeadline(time.Now().Add(wsReadTimeout))
	}

	var header [2]byte
	if _, err = io.ReadFull(ws.reader, header[:]); err != nil {
		return 0, nil, err
	}

	opcode = int(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(ws.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(ws.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	if length > maxFrameSize {
		return 0, nil, fmt.Errorf("frame size %d exceeds max %d", length, maxFrameSize)
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(ws.reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(ws.reader, payload); err != nil {
			return 0, nil, err
		}
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func (ws *WSConn) writeFrame(opcode int, payload []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if nc, ok := ws.conn.(net.Conn); ok {
		_ = nc.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	}

	length := len(payload)
	// Single buffer: max header (2+8+4=14) + payload
	buf := make([]byte, 0, 14+length)

	// Header
	buf = append(buf, 0x80|byte(opcode)) // FIN + opcode
	switch {
	case length <= 125:
		buf = append(buf, 0x80|byte(length))
	case length <= 65535:
		buf = append(buf, 0x80|126, byte(length>>8), byte(length))
	default:
		buf = append(buf, 0x80|127,
			byte(length>>56), byte(length>>48), byte(length>>40), byte(length>>32),
			byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}

	// Mask key
	var maskKey [4]byte
	_, _ = rand.Read(maskKey[:])
	buf = append(buf, maskKey[:]...)

	// Masked payload
	for i, b := range payload {
		buf = append(buf, b^maskKey[i%4])
	}

	_, err := ws.conn.Write(buf)
	return err
}
