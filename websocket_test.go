package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWriteFrameMasked(t *testing.T) {
	// Verify that writeFrame produces a valid masked client frame
	var buf bytes.Buffer
	ws := &WSConn{conn: &nopCloser{readWriter: &buf}}

	payload := []byte("hello")
	if err := ws.writeFrame(opText, payload); err != nil {
		t.Fatal(err)
	}

	frame := buf.Bytes()

	// First byte: FIN + opcode
	if frame[0] != 0x81 { // 0x80 (FIN) | 0x01 (text)
		t.Errorf("first byte: got %#x, want 0x81", frame[0])
	}

	// Second byte: MASK + length
	if frame[1] != 0x85 { // 0x80 (mask) | 5 (length)
		t.Errorf("second byte: got %#x, want 0x85", frame[1])
	}

	// Mask key is bytes 2-5
	maskKey := frame[2:6]
	maskedPayload := frame[6:]

	// Unmask and verify
	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	if string(maskedPayload) != "hello" {
		t.Errorf("unmasked payload: got %q, want %q", maskedPayload, "hello")
	}
}

func TestWriteFrameExtendedLength(t *testing.T) {
	// Test 16-bit extended length (126-65535 bytes)
	var buf bytes.Buffer
	ws := &WSConn{conn: &nopCloser{readWriter: &buf}}

	payload := make([]byte, 300) // > 125, uses 2-byte extended
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

func TestReadFrame(t *testing.T) {
	// Build an unmasked server frame
	var buf bytes.Buffer
	payload := []byte("world")
	buf.WriteByte(0x81) // FIN + text
	buf.WriteByte(byte(len(payload)))
	buf.Write(payload)

	ws := &WSConn{conn: &nopCloser{readWriter: &buf}}
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

func TestReadFramePingPong(t *testing.T) {
	// Server sends a ping, ReadMessage should auto-respond with pong and continue
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
	ws := &WSConn{conn: &nopCloser{readWriter: rw}}

	data, _, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Errorf("got %q, want %q", data, "data")
	}

	// Verify pong was written
	if len(rw.written) == 0 {
		t.Error("expected pong frame to be written")
	}
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
