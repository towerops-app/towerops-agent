package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
)

const (
	opText   = 1
	opBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10
)

// WSConn is a minimal RFC 6455 WebSocket client.
type WSConn struct {
	conn io.ReadWriteCloser
	mu   sync.Mutex // serializes writes
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
		conn, err = tls.Dial("tcp", host, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = net.Dial("tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	// Generate random key for Sec-WebSocket-Key
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, fmt.Errorf("generate key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write handshake: %w", err)
	}

	// Read HTTP response (look for 101 Switching Protocols)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "101") {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %s", strings.SplitN(resp, "\r\n", 2)[0])
	}

	return &WSConn{conn: conn}, nil
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
			ws.writeFrame(opClose, nil) // best-effort close reply
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
	ws.writeFrame(opClose, nil) // best-effort
	return ws.conn.Close()
}

func (ws *WSConn) readFrame() (opcode int, payload []byte, err error) {
	var header [2]byte
	if _, err = io.ReadFull(ws.conn, header[:]); err != nil {
		return 0, nil, err
	}

	opcode = int(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(ws.conn, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(ws.conn, payload); err != nil {
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
	// Max header: 2 + 8 + 4 (mask) = 14 bytes
	header := make([]byte, 2, 14)
	header[0] = 0x80 | byte(opcode) // FIN + opcode
	header[1] = 0x80               // masked (client must mask)

	switch {
	case length <= 125:
		header[1] |= byte(length)
	case length <= 65535:
		header[1] |= 126
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		header = append(header, ext...)
	default:
		header[1] |= 127
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		header = append(header, ext...)
	}

	// Generate mask key
	maskKey := make([]byte, 4)
	rand.Read(maskKey)
	header = append(header, maskKey...)

	// Mask payload
	masked := make([]byte, length)
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	if _, err := ws.conn.Write(header); err != nil {
		return err
	}
	if length > 0 {
		if _, err := ws.conn.Write(masked); err != nil {
			return err
		}
	}
	return nil
}
