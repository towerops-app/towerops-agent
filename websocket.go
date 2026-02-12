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
func WSDial(rawURL string) (*WSConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	useTLS := u.Scheme == "wss"
	host := u.Host
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var conn net.Conn
	if useTLS {
		conn, err = tlsDial("tcp", host)
	} else {
		conn, err = netDial("tcp", host)
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

	// Read HTTP response (look for 101 Switching Protocols)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "101") {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake failed: %s", strings.SplitN(resp, "\r\n", 2)[0])
	}

	// Verify Sec-WebSocket-Accept per RFC 6455
	expectedAccept := computeAcceptKey(key)
	acceptFound := false
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept: ") {
			actual := strings.TrimSpace(line[len("Sec-WebSocket-Accept: "):])
			if actual != expectedAccept {
				_ = conn.Close()
				return nil, fmt.Errorf("invalid accept key: got %q, want %q", actual, expectedAccept)
			}
			acceptFound = true
			break
		}
	}
	if !acceptFound {
		_ = conn.Close()
		return nil, fmt.Errorf("missing Sec-WebSocket-Accept header")
	}

	// Clear handshake deadline — normal operation uses no deadline
	_ = conn.SetDeadline(time.Time{})

	return &WSConn{conn: conn, reader: bufio.NewReaderSize(conn, 8192)}, nil
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

func (ws *WSConn) readFrame() (opcode int, payload []byte, err error) {
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
