package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestWriteFrameMasked(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	payload := []byte("hello")
	if err := ws.writeFrame(opText, payload); err != nil {
		t.Fatal(err)
	}

	frame := buf.Bytes()

	if frame[0] != 0x81 {
		t.Errorf("first byte: got %#x, want 0x81", frame[0])
	}

	if frame[1] != 0x85 {
		t.Errorf("second byte: got %#x, want 0x85", frame[1])
	}

	maskKey := frame[2:6]
	maskedPayload := frame[6:]

	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	if string(maskedPayload) != "hello" {
		t.Errorf("unmasked payload: got %q, want %q", maskedPayload, "hello")
	}
}

func TestWriteFrame16BitLength(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	payload := make([]byte, 300)
	if err := ws.writeFrame(opBinary, payload); err != nil {
		t.Fatal(err)
	}

	frame := buf.Bytes()
	if frame[1]&0x7F != 126 {
		t.Errorf("expected 126 length marker, got %d", frame[1]&0x7F)
	}
	extLen := binary.BigEndian.Uint16(frame[2:4])
	if extLen != 300 {
		t.Errorf("extended length: got %d, want 300", extLen)
	}
}

func TestWriteFrame64BitLength(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	payload := make([]byte, 70000) // > 65535, uses 8-byte extended
	if err := ws.writeFrame(opBinary, payload); err != nil {
		t.Fatal(err)
	}

	frame := buf.Bytes()
	if frame[1]&0x7F != 127 {
		t.Errorf("expected 127 length marker, got %d", frame[1]&0x7F)
	}
	extLen := binary.BigEndian.Uint64(frame[2:10])
	if extLen != 70000 {
		t.Errorf("extended length: got %d, want 70000", extLen)
	}
}

func TestReadFrame(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("world")
	buf.WriteByte(0x81) // FIN + text
	buf.WriteByte(byte(len(payload)))
	buf.Write(payload)

	ws := testWSConn(&nopCloser{readWriter: &buf})
	opcode, data, err := ws.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if opcode != opText {
		t.Errorf("opcode: got %d, want %d", opcode, opText)
	}
	if string(data) != "world" {
		t.Errorf("data: got %q, want %q", data, "world")
	}
}

func TestReadFrame16BitLength(t *testing.T) {
	var buf bytes.Buffer
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	buf.WriteByte(0x82) // FIN + binary
	buf.WriteByte(126)  // 16-bit extended length
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], 300)
	buf.Write(extLen[:])
	buf.Write(payload)

	ws := testWSConn(&nopCloser{readWriter: &buf})
	opcode, data, err := ws.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if opcode != opBinary {
		t.Errorf("opcode: got %d, want %d", opcode, opBinary)
	}
	if len(data) != 300 {
		t.Errorf("data length: got %d, want 300", len(data))
	}
}

func TestReadFrame64BitLength(t *testing.T) {
	var buf bytes.Buffer
	payload := make([]byte, 70000)
	buf.WriteByte(0x82) // FIN + binary
	buf.WriteByte(127)  // 64-bit extended length
	var extLen [8]byte
	binary.BigEndian.PutUint64(extLen[:], 70000)
	buf.Write(extLen[:])
	buf.Write(payload)

	ws := testWSConn(&nopCloser{readWriter: &buf})
	opcode, data, err := ws.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if opcode != opBinary {
		t.Errorf("opcode: got %d, want %d", opcode, opBinary)
	}
	if len(data) != 70000 {
		t.Errorf("data length: got %d, want 70000", len(data))
	}
}

func TestReadFrameMasked(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("test")
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	buf.WriteByte(0x81)                      // FIN + text
	buf.WriteByte(0x80 | byte(len(payload))) // masked + length
	buf.Write(maskKey[:])
	buf.Write(masked)

	ws := testWSConn(&nopCloser{readWriter: &buf})
	opcode, data, err := ws.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if opcode != opText {
		t.Errorf("opcode: got %d, want %d", opcode, opText)
	}
	if string(data) != "test" {
		t.Errorf("data: got %q, want %q", data, "test")
	}
}

func TestReadMessageClose(t *testing.T) {
	var buf bytes.Buffer
	// Close frame
	buf.WriteByte(0x80 | byte(opClose))
	buf.WriteByte(0) // no payload

	rw := &captureWriter{Reader: &buf}
	ws := testWSConn(&nopCloser{readWriter: rw})

	_, opcode, err := ws.ReadMessage()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
	if opcode != opClose {
		t.Errorf("opcode: got %d, want %d", opcode, opClose)
	}
	// Verify close reply was sent
	if len(rw.written) == 0 {
		t.Error("expected close reply frame to be written")
	}
}

func TestReadFramePingPong(t *testing.T) {
	var buf bytes.Buffer

	// Ping frame
	buf.WriteByte(0x80 | byte(opPing))
	buf.WriteByte(0) // no payload

	// Then a text frame
	text := []byte("data")
	buf.WriteByte(0x81)
	buf.WriteByte(byte(len(text)))
	buf.Write(text)

	rw := &captureWriter{Reader: &buf}
	ws := testWSConn(&nopCloser{readWriter: rw})

	data, _, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Errorf("got %q, want %q", data, "data")
	}

	if len(rw.written) == 0 {
		t.Error("expected pong frame to be written")
	}
}

func TestReadFrame16BitLengthError(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81) // FIN + text
	buf.WriteByte(126)  // 16-bit length indicator, but no length bytes follow

	ws := testWSConn(&nopCloser{readWriter: &buf})
	_, _, err := ws.readFrame()
	if err == nil {
		t.Error("expected error for truncated 16-bit length")
	}
}

func TestReadFrame64BitLengthError(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81) // FIN + text
	buf.WriteByte(127)  // 64-bit length indicator, but no length bytes follow

	ws := testWSConn(&nopCloser{readWriter: &buf})
	_, _, err := ws.readFrame()
	if err == nil {
		t.Error("expected error for truncated 64-bit length")
	}
}

func TestReadFrameMaskKeyError(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81)        // FIN + text
	buf.WriteByte(0x80 | 0x01) // masked + length 1, but no mask key or payload

	ws := testWSConn(&nopCloser{readWriter: &buf})
	_, _, err := ws.readFrame()
	if err == nil {
		t.Error("expected error for missing mask key")
	}
}

func TestReadFramePayloadError(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81) // FIN + text
	buf.WriteByte(5)    // length 5, but no payload

	ws := testWSConn(&nopCloser{readWriter: &buf})
	_, _, err := ws.readFrame()
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestWriteFrameHeaderError(t *testing.T) {
	ws := testWSConn(&failOnWriteBuffer{Buffer: bytes.NewBuffer(nil)})
	err := ws.writeFrame(opText, []byte("hello"))
	if err == nil {
		t.Error("expected write error")
	}
}


func TestReadMessageError(t *testing.T) {
	// Empty buffer causes immediate EOF on readFrame
	buf := bytes.NewBuffer(nil)
	ws := testWSConn(&nopCloser{readWriter: buf})
	_, _, err := ws.ReadMessage()
	if err == nil {
		t.Error("expected error for empty buffer")
	}
}

func TestReadMessagePongError(t *testing.T) {
	// Ping frame followed by write failure for pong
	var buf bytes.Buffer
	buf.WriteByte(0x80 | byte(opPing))
	buf.WriteByte(0)

	ws := testWSConn(&nopCloser{readWriter: &failOnWriteBuffer{Buffer: &buf}})
	_, _, err := ws.ReadMessage()
	if err == nil {
		t.Error("expected pong write error")
	}
}

func TestReadFrameEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN + binary
	buf.WriteByte(0)    // zero length

	ws := testWSConn(&nopCloser{readWriter: &buf})
	opcode, data, err := ws.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if opcode != opBinary {
		t.Errorf("opcode: got %d, want %d", opcode, opBinary)
	}
	if len(data) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(data))
	}
}

func TestWriteFrameEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	if err := ws.writeFrame(opClose, nil); err != nil {
		t.Fatal(err)
	}

	frame := buf.Bytes()
	if frame[0]&0x0F != opClose {
		t.Errorf("expected close opcode, got %d", frame[0]&0x0F)
	}
	// Length should be 0 (masked)
	if frame[1]&0x7F != 0 {
		t.Errorf("expected 0 length, got %d", frame[1]&0x7F)
	}
}

// failOnWriteBuffer reads from Buffer but fails on Write.
type failOnWriteBuffer struct {
	*bytes.Buffer
}

func (f *failOnWriteBuffer) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write failed")
}
func (f *failOnWriteBuffer) Close() error { return nil }

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	if err := ws.WriteText([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Verify it wrote a text frame (opcode 1)
	frame := buf.Bytes()
	if frame[0]&0x0F != opText {
		t.Errorf("expected text opcode, got %d", frame[0]&0x0F)
	}
}

func TestClose(t *testing.T) {
	var buf bytes.Buffer
	ws := testWSConn(&nopCloser{readWriter: &buf})

	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify it wrote a close frame (opcode 8)
	frame := buf.Bytes()
	if len(frame) == 0 {
		t.Fatal("expected close frame to be written")
	}
	if frame[0]&0x0F != opClose {
		t.Errorf("expected close opcode, got %d", frame[0]&0x0F)
	}
}

func TestWSDial(t *testing.T) {
	// Start a test TCP server that responds with a valid WebSocket upgrade
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		_ = string(buf[:n]) // Read the request

		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Keep connection open briefly for the test
		buf2 := make([]byte, 1)
		_, _ = conn.Read(buf2)
	}()

	addr := ln.Addr().String()
	ws, err := WSDial("ws://" + addr + "/socket")
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.Close()
}

func TestWSDialHandshakeFailed(t *testing.T) {
	// Start a test HTTP server that returns 403
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)

		resp := "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
	}()

	addr := ln.Addr().String()
	_, err = WSDial("ws://" + addr + "/socket")
	if err == nil {
		t.Error("expected handshake error")
	}
	if !strings.Contains(err.Error(), "handshake failed") {
		t.Errorf("expected 'handshake failed' in error, got: %v", err)
	}
}

func TestWSDialReadHandshakeError(t *testing.T) {
	// Server accepts connection but immediately closes without sending response
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			// Read the request then close immediately
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().String()
	_, err = WSDial("ws://" + addr + "/socket")
	if err == nil {
		t.Error("expected read handshake error")
	}
}

func TestWSDialGenerateKeyError(t *testing.T) {
	origRandRead := randRead
	defer func() { randRead = origRandRead }()
	randRead = func(b []byte) (int, error) {
		return 0, fmt.Errorf("entropy exhausted")
	}

	// Start a TCP server that accepts connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().String()
	_, err = WSDial("ws://" + addr + "/socket")
	if err == nil {
		t.Error("expected generate key error")
	}
	if !strings.Contains(err.Error(), "generate key") {
		t.Errorf("expected 'generate key' in error, got: %v", err)
	}
}

func TestWSDialWriteHandshakeError(t *testing.T) {
	origDial := netDial
	defer func() { netDial = origDial }()

	netDial = func(network, addr string) (net.Conn, error) {
		// Return a connection whose Write always fails
		client, _ := net.Pipe()
		_ = client.Close() // Close immediately so Write fails
		return client, nil
	}

	_, err := WSDial("ws://127.0.0.1:9999/socket")
	if err == nil {
		t.Error("expected write handshake error")
	}
	if !strings.Contains(err.Error(), "write handshake") {
		t.Errorf("expected 'write handshake' in error, got: %v", err)
	}
}

func TestWSDialBadURL(t *testing.T) {
	_, err := WSDial("://bad url")
	if err == nil {
		t.Error("expected parse error for bad URL")
	}
}

func TestWSDialDefaultPorts(t *testing.T) {
	// Test that ws:// defaults to port 80 — will fail to connect but verifies URL parsing
	_, err := WSDial("ws://127.0.0.1/path")
	if err == nil {
		t.Error("expected connection error (nothing on port 80)")
	}

	// Test that wss:// defaults to port 443
	_, err = WSDial("wss://127.0.0.1/path")
	if err == nil {
		t.Error("expected connection error (nothing on port 443)")
	}
}

func TestWSDialRealHTTPServer(t *testing.T) {
	// Test with a real HTTP server that sends proper 101 upgrade
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, brw, _ := hj.Hijack()
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		// Keep alive briefly
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	go func() { _ = http.Serve(ln, mux) }()

	addr := ln.Addr().String()
	ws, err := WSDial("ws://" + addr + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.Close()
}

func testWSConn(rw io.ReadWriteCloser) *WSConn {
	return &WSConn{conn: rw, reader: bufio.NewReader(rw)}
}

// nopCloser wraps a ReadWriter with a no-op Close.
type nopCloser struct {
	readWriter interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
	}
}

func (n *nopCloser) Read(p []byte) (int, error)  { return n.readWriter.Read(p) }
func (n *nopCloser) Write(p []byte) (int, error) { return n.readWriter.Write(p) }
func (n *nopCloser) Close() error                { return nil }

// captureWriter captures written data while reading from a separate Reader.
type captureWriter struct {
	Reader  *bytes.Buffer
	written []byte
}

func (c *captureWriter) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *captureWriter) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *captureWriter) Close() error { return nil }
