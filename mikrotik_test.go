// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"pgregory.net/rapid"
)

type nopCloser struct {
	readWriter io.ReadWriter
}

func (n *nopCloser) Read(p []byte) (int, error)  { return n.readWriter.Read(p) }
func (n *nopCloser) Write(p []byte) (int, error) { return n.readWriter.Write(p) }
func (n *nopCloser) Close() error                { return nil }

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func (w *shortWriter) Close() error { return nil }

func TestEncodeLength(t *testing.T) {
	tests := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x80}},
		{255, []byte{0x80, 0xFF}},
		{256, []byte{0x81, 0x00}},
		{16383, []byte{0xBF, 0xFF}},
		{16384, []byte{0xC0, 0x40, 0x00}},
		{2097151, []byte{0xDF, 0xFF, 0xFF}},
		{2097152, []byte{0xE0, 0x20, 0x00, 0x00}},
		{268435456, []byte{0xF0, 0x10, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		got := encodeLength(tt.n)
		if len(got) != len(tt.want) {
			t.Errorf("encodeLength(%d) = %v, want %v", tt.n, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("encodeLength(%d) = %v, want %v", tt.n, got, tt.want)
				break
			}
		}
	}
}

func TestWriteSentenceHandlesShortWrites(t *testing.T) {
	conn := &shortWriter{}
	client := &mikrotikClient{conn: conn}
	if err := client.writeSentence([]string{"/system/resource/print"}); err != nil {
		t.Fatalf("writeSentence: %v", err)
	}
	want := append(encodeLength(len("/system/resource/print")), "/system/resource/print"...)
	want = append(want, 0)
	if !bytes.Equal(conn.Bytes(), want) {
		t.Fatalf("written bytes = %x, want %x", conn.Bytes(), want)
	}
}

func TestReadSentenceRejectsTooManyWords(t *testing.T) {
	var encoded bytes.Buffer
	for range maxMikrotikWords + 1 {
		encoded.WriteByte(1)
		encoded.WriteByte('x')
	}
	encoded.WriteByte(0)

	client := &mikrotikClient{conn: &nopCloser{readWriter: &encoded}}
	_, err := client.readSentence()
	if err == nil || !strings.Contains(err.Error(), "exceeds 10000 words") {
		t.Fatalf("readSentence error = %v, want word limit", err)
	}
}

func TestParseMikrotikAttrs(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  map[string]string
	}{
		{"empty", nil, map[string]string{}},
		{"single", []string{"=name=MyRouter"}, map[string]string{"name": "MyRouter"}},
		{"multiple", []string{"=name=MyRouter", "=model=RB450Gx4"}, map[string]string{"name": "MyRouter", "model": "RB450Gx4"}},
		{"equals in value", []string{"=comment=a=b=c"}, map[string]string{"comment": "a=b=c"}},
		{"ignores non-attr", []string{"!re", "=name=test"}, map[string]string{"name": "test"}},
		{"empty value", []string{"=disabled="}, map[string]string{"disabled": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMikrotikAttrs(tt.words)
			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// encodeSentence encodes a list of words into RouterOS binary format.
func encodeSentence(words []string) []byte {
	var buf []byte
	for _, w := range words {
		buf = append(buf, encodeLength(len(w))...)
		buf = append(buf, w...)
	}
	buf = append(buf, 0) // empty word terminates sentence
	return buf
}

func TestReadLength(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"1-byte (0)", []byte{0x00}, 0},
		{"1-byte (5)", []byte{0x05}, 5},
		{"1-byte (127)", []byte{0x7F}, 127},
		{"2-byte (128)", []byte{0x80, 0x80}, 128},
		{"2-byte (16383)", []byte{0xBF, 0xFF}, 16383},
		{"3-byte (16384)", []byte{0xC0, 0x40, 0x00}, 16384},
		{"3-byte (2097151)", []byte{0xDF, 0xFF, 0xFF}, 2097151},
		{"4-byte (2097152)", []byte{0xE0, 0x20, 0x00, 0x00}, 2097152},
		{"5-byte", []byte{0xF0, 0x10, 0x00, 0x00, 0x00}, 0x10000000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &mikrotikClient{conn: &nopCloser{readWriter: bytes.NewBuffer(tt.data)}}
			got, err := c.readLength()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReadWord(t *testing.T) {
	t.Run("normal word", func(t *testing.T) {
		word := "!done"
		var buf bytes.Buffer
		buf.Write(encodeLength(len(word)))
		buf.WriteString(word)
		c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
		got, err := c.readWord()
		if err != nil {
			t.Fatal(err)
		}
		if got != word {
			t.Errorf("got %q, want %q", got, word)
		}
	})

	t.Run("empty word", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{0x00})
		c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
		got, err := c.readWord()
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestReadSentence(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(encodeSentence([]string{"!re", "=name=eth0", "=type=ether"}))
	c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
	words, err := c.readSentence()
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 3 {
		t.Fatalf("got %d words, want 3", len(words))
	}
	if words[0] != "!re" || words[1] != "=name=eth0" || words[2] != "=type=ether" {
		t.Errorf("unexpected words: %v", words)
	}
}

func TestReadResponse(t *testing.T) {
	tests := []struct {
		name         string
		sentences    [][]string
		wantCount    int
		wantErr      string
		wantFatalErr bool
	}{
		{
			name:      "done only",
			sentences: [][]string{{"!done"}},
			wantCount: 0,
		},
		{
			name:      "done with attrs",
			sentences: [][]string{{"!done", "=ret=ok"}},
			wantCount: 1,
		},
		{
			name:      "re + done",
			sentences: [][]string{{"!re", "=name=eth0"}, {"!re", "=name=eth1"}, {"!done"}},
			wantCount: 2,
		},
		{
			name:      "trap + done",
			sentences: [][]string{{"!trap", "=message=no such command"}, {"!done"}},
			wantErr:   "no such command",
			wantCount: 0,
		},
		{
			name:      "trap without message + done",
			sentences: [][]string{{"!trap"}, {"!done"}},
			wantErr:   "unknown error",
			wantCount: 0,
		},
		{
			name:         "fatal",
			sentences:    [][]string{{"!fatal", "=message=connection reset"}},
			wantFatalErr: true,
		},
		{
			name:         "fatal without message",
			sentences:    [][]string{{"!fatal"}},
			wantFatalErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			for _, s := range tt.sentences {
				buf.Write(encodeSentence(s))
			}
			c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
			resp, err := c.readResponse()
			if tt.wantFatalErr {
				if err == nil {
					t.Error("expected fatal error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(resp.sentences) != tt.wantCount {
				t.Errorf("got %d sentences, want %d", len(resp.sentences), tt.wantCount)
			}
			if resp.err != tt.wantErr {
				t.Errorf("err: got %q, want %q", resp.err, tt.wantErr)
			}
		})
	}
}

func TestWriteSentence(t *testing.T) {
	var buf bytes.Buffer
	c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
	words := []string{"/interface/print", "=detail="}
	if err := c.writeSentence(words); err != nil {
		t.Fatal(err)
	}

	// Read it back
	c2 := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
	got, err := c2.readSentence()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(words) {
		t.Fatalf("got %d words, want %d", len(got), len(words))
	}
	for i, w := range words {
		if got[i] != w {
			t.Errorf("word[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

func TestExecute(t *testing.T) {
	// Use io.Pipe to simulate a full-duplex connection
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()

	conn := &readWriteCloser{r: clientR, w: clientW}
	c := &mikrotikClient{conn: conn}

	// Server goroutine: read command, write response
	go func() {
		defer func() { _ = serverW.Close() }()
		sc := &mikrotikClient{conn: &readWriteCloser{r: serverR, w: serverW}}
		// Read the command sentence
		_, _ = sc.readSentence()
		// Write !done response
		_ = sc.writeSentence([]string{"!done", "=ret=ok"})
	}()

	resp, err := c.execute("/system/identity/print", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.err != "" {
		t.Errorf("unexpected error: %s", resp.err)
	}
	if len(resp.sentences) != 1 {
		t.Fatalf("got %d sentences, want 1", len(resp.sentences))
	}
	if resp.sentences[0].attributes["ret"] != "ok" {
		t.Errorf("got ret=%q, want %q", resp.sentences[0].attributes["ret"], "ok")
	}
}

func TestExecuteWithArgs(t *testing.T) {
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()

	conn := &readWriteCloser{r: clientR, w: clientW}
	c := &mikrotikClient{conn: conn}

	var receivedWords []string
	go func() {
		defer func() { _ = serverW.Close() }()
		sc := &mikrotikClient{conn: &readWriteCloser{r: serverR, w: serverW}}
		receivedWords, _ = sc.readSentence()
		_ = sc.writeSentence([]string{"!done"})
	}()

	args := map[string]string{
		"name":      "admin",
		"?type":     "ether",
		".proplist": "name,type",
	}
	_, err := c.execute("/interface/print", args)
	if err != nil {
		t.Fatal(err)
	}

	// Verify command word
	if len(receivedWords) == 0 || receivedWords[0] != "/interface/print" {
		t.Errorf("expected command /interface/print, got: %v", receivedWords)
	}

	// Verify args formatting: ?-prefix and .-prefix get k=v, others get =k=v
	wordSet := make(map[string]bool)
	for _, w := range receivedWords[1:] {
		wordSet[w] = true
	}
	if !wordSet["=name=admin"] {
		t.Error("expected =name=admin in words")
	}
	if !wordSet["?type=ether"] {
		t.Error("expected ?type=ether in words")
	}
	if !wordSet[".proplist=name,type"] {
		t.Error("expected .proplist=name,type in words")
	}
}

type quitBlockingConn struct {
	bytes.Buffer
	closed chan struct{}
	once   sync.Once
}

func (c *quitBlockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *quitBlockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestMikrotikCloseDoesNotWaitForResponse(t *testing.T) {
	conn := &quitBlockingConn{closed: make(chan struct{})}
	client := &mikrotikClient{conn: conn}
	done := make(chan error, 1)

	go func() {
		done <- client.close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close()
		<-done
		t.Fatal("close waited for a /quit response")
	}

	select {
	case <-conn.closed:
	default:
		t.Fatal("connection was not closed")
	}

	want := encodeSentence([]string{"/quit"})
	if !bytes.Equal(conn.Bytes(), want) {
		t.Fatalf("written bytes = %x, want /quit sentence %x", conn.Bytes(), want)
	}
}

func TestMikrotikConnect(t *testing.T) {
	// Start a test TCP server that speaks mikrotik binary protocol
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
		sc := &mikrotikClient{conn: conn}
		// Read the /login command
		_, _ = sc.readSentence()
		// Respond with !done (login success)
		_ = sc.writeSentence([]string{"!done"})
		// Read the /quit command on close
		_, _ = sc.readSentence()
		// Respond with !fatal to close
		_ = sc.writeSentence([]string{"!fatal"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	client, err := mikrotikConnect(context.Background(), "127.0.0.1", portNum, "admin", "pass", false)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.close()
}

func TestMikrotikConnectAuthError(t *testing.T) {
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
		sc := &mikrotikClient{conn: conn}
		_, _ = sc.readSentence()
		// Respond with trap error + done
		_ = sc.writeSentence([]string{"!trap", "=message=invalid user"})
		_ = sc.writeSentence([]string{"!done"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err = mikrotikConnect(context.Background(), "127.0.0.1", portNum, "admin", "wrong", false)
	if err == nil {
		t.Error("expected auth error")
	}
}

func TestMikrotikConnectFatalError(t *testing.T) {
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
		sc := &mikrotikClient{conn: conn}
		_, _ = sc.readSentence()
		// Respond with fatal error
		_ = sc.writeSentence([]string{"!fatal", "=message=connection reset"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err = mikrotikConnect(context.Background(), "127.0.0.1", portNum, "admin", "pass", false)
	if err == nil {
		t.Error("expected fatal error")
	}
}

func TestMikrotikConnectRefused(t *testing.T) {
	// Connect to a port with nothing listening
	_, err := mikrotikConnect(context.Background(), "127.0.0.1", 1, "admin", "pass", false)
	if err == nil {
		t.Error("expected connection refused")
	}
}

func TestMikrotikConnectSSL(t *testing.T) {
	// SSL connect to a port with nothing listening — tests the TLS dialer path
	_, err := mikrotikConnect(context.Background(), "127.0.0.1", 1, "admin", "pass", true)
	if err == nil {
		t.Error("expected connection error with SSL")
	}
}

func TestMikrotikConnectSSLWithServer(t *testing.T) {
	// Generate a self-signed cert at runtime
	cert := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	origStore := globalHostKeys
	t.Cleanup(func() { globalHostKeys = origStore })
	globalHostKeys = newHostKeyStore(filepath.Join(t.TempDir(), "hosts.json"))

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sc := &mikrotikClient{conn: conn}
		_, _ = sc.readSentence()
		_ = sc.writeSentence([]string{"!done"})
		_, _ = sc.readSentence()
		_ = sc.writeSentence([]string{"!fatal"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	client, err := mikrotikConnect(context.Background(), "127.0.0.1", portNum, "admin", "pass", true)
	if err != nil {
		t.Fatalf("expected TLS connection to succeed: %v", err)
	}
	_ = client.close()
}

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}

func TestReadResponseEmptySentence(t *testing.T) {
	// An empty sentence (just the terminator byte) should be skipped
	var buf bytes.Buffer
	buf.WriteByte(0) // empty sentence
	buf.Write(encodeSentence([]string{"!done"}))
	c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
	resp, err := c.readResponse()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.sentences) != 0 {
		t.Errorf("expected 0 sentences, got %d", len(resp.sentences))
	}
}

func TestReadSentenceWithNetConn(t *testing.T) {
	// Test readSentence with a real net.Conn to trigger SetReadDeadline path
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go func() {
		_, _ = server.Write(encodeSentence([]string{"!done"}))
	}()

	c := &mikrotikClient{conn: client}
	words, err := c.readSentence()
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 1 || words[0] != "!done" {
		t.Errorf("unexpected words: %v", words)
	}
}

func TestExecuteWriteError(t *testing.T) {
	c := &mikrotikClient{conn: &failWriter{}}
	_, err := c.execute("/test", nil)
	if err == nil {
		t.Error("expected write error")
	}
}

func TestReadWordError(t *testing.T) {
	// Empty buffer causes read error
	buf := bytes.NewBuffer([]byte{0x05}) // length 5, but no data following
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readWord()
	if err == nil {
		t.Error("expected read error for truncated word")
	}
}

func TestReadLengthError(t *testing.T) {
	// Empty buffer causes EOF
	buf := bytes.NewBuffer(nil)
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readLength()
	if err == nil {
		t.Error("expected read error for empty buffer")
	}
}

func TestReadLength2ByteError(t *testing.T) {
	// 2-byte length with truncated second byte
	buf := bytes.NewBuffer([]byte{0x80}) // needs 1 more byte
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readLength()
	if err == nil {
		t.Error("expected error for truncated 2-byte length")
	}
}

func TestReadLength3ByteError(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xC0}) // needs 2 more bytes
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readLength()
	if err == nil {
		t.Error("expected error for truncated 3-byte length")
	}
}

func TestReadLength4ByteError(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xE0}) // needs 3 more bytes
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readLength()
	if err == nil {
		t.Error("expected error for truncated 4-byte length")
	}
}

func TestReadLength5ByteError(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xF0}) // needs 4 more bytes
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readLength()
	if err == nil {
		t.Error("expected error for truncated 5-byte length")
	}
}

func TestReadWordExceedsMaxSize(t *testing.T) {
	oversize := maxMikrotikWordSize + 1
	var buf bytes.Buffer
	buf.Write(encodeLength(oversize))
	// Don't need to write the payload — should reject before reading it
	c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
	_, err := c.readWord()
	if err == nil {
		t.Error("expected error for word exceeding max size")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("expected 'exceeds max' in error, got: %v", err)
	}
}

func TestReadSentenceError(t *testing.T) {
	// Buffer with valid length byte but truncated word data
	buf := bytes.NewBuffer([]byte{0x03, 'a'}) // length=3 but only 1 byte of data
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readSentence()
	if err == nil {
		t.Error("expected error for truncated sentence")
	}
}

func TestReadResponseReadError(t *testing.T) {
	// Empty buffer causes immediate error
	buf := bytes.NewBuffer(nil)
	c := &mikrotikClient{conn: &nopCloser{readWriter: buf}}
	_, err := c.readResponse()
	if err == nil {
		t.Error("expected error for empty buffer")
	}
}

// failWriter always returns an error on Write.
type failWriter struct{}

func (f *failWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f *failWriter) Write(p []byte) (int, error) { return 0, fmt.Errorf("write failed") }
func (f *failWriter) Close() error                { return nil }

// readWriteCloser combines separate reader and writer into io.ReadWriteCloser.
type readWriteCloser struct {
	r io.Reader
	w io.Writer
}

func (rwc *readWriteCloser) Read(p []byte) (int, error)  { return rwc.r.Read(p) }
func (rwc *readWriteCloser) Write(p []byte) (int, error) { return rwc.w.Write(p) }
func (rwc *readWriteCloser) Close() error {
	if c, ok := rwc.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func TestMikrotikConnectSSLTOFUMismatch(t *testing.T) {
	cert := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Pre-populate the host key store with the wrong fingerprint.
	origStore := globalHostKeys
	t.Cleanup(func() { globalHostKeys = origStore })
	globalHostKeys = newHostKeyStore(filepath.Join(t.TempDir(), "hosts.json"))

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	// Pre-register wrong fingerprint so TOFU verification fails
	store := getHostKeyStore()
	store.keys["tls:"+net.JoinHostPort("127.0.0.1", port)] = "wrong_fingerprint"

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Complete TLS handshake so client gets peer certificates
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
		time.Sleep(time.Second)
	}()

	_, err = mikrotikConnect(context.Background(), "127.0.0.1", portNum, "admin", "pass", true)
	if err == nil {
		t.Error("expected TOFU verification failure")
	}
	if !strings.Contains(err.Error(), "TOFU verification failed") {
		t.Errorf("expected 'TOFU verification failed' in error, got: %v", err)
	}
}

// hmTReadConn adapts any io.Reader into an io.ReadWriteCloser whose writes are
// discarded, so large synthetic RouterOS streams can be fed lazily.
type hmTReadConn struct {
	r io.Reader
}

func (c *hmTReadConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *hmTReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *hmTReadConn) Close() error                { return nil }

// hmTZeroReader is an infinite source of NUL bytes.
type hmTZeroReader struct{}

func (hmTZeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// hmTFillerWord returns readers producing a length prefix followed by n bytes.
func hmTFillerWord(n int) []io.Reader {
	return []io.Reader{
		bytes.NewReader(encodeLength(n)),
		io.LimitReader(hmTZeroReader{}, int64(n)),
	}
}

func TestHmReadResponseTrapWithoutMessage(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(encodeSentence([]string{"!trap", "=category=0"}))
	buf.Write(encodeSentence([]string{"!done"}))
	c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}

	resp, err := c.readResponse()
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if resp.err != "unknown error" {
		t.Fatalf("expected fallback trap error, got %q", resp.err)
	}
	if len(resp.sentences) != 0 {
		t.Fatalf("expected no data sentences, got %v", resp.sentences)
	}
}

func TestHmReadResponseExceedsMaxBytes(t *testing.T) {
	// Two individually valid words in separate sentences exceed the aggregate
	// response budget.
	const word = 9 << 20
	var readers []io.Reader
	for range 2 {
		readers = append(readers, bytes.NewReader(append(encodeLength(len("!re")), "!re"...)))
		readers = append(readers, hmTFillerWord(word)...)
		readers = append(readers, bytes.NewReader([]byte{0}))
	}
	c := &mikrotikClient{conn: &hmTReadConn{r: io.MultiReader(readers...)}}

	_, err := c.readResponse()
	if err == nil {
		t.Fatal("expected aggregate response size error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("response exceeds %d bytes", maxMikrotikResponse)) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHmReadResponseExceedsMaxSentences(t *testing.T) {
	// Empty sentences are skipped, so a stream of terminators exhausts the
	// sentence budget without ever producing a !done.
	empties := bytes.Repeat([]byte{0}, maxMikrotikSentences+1)
	c := &mikrotikClient{conn: &nopCloser{readWriter: bytes.NewBuffer(empties)}}

	_, err := c.readResponse()
	if err == nil {
		t.Fatal("expected sentence count error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("response exceeds %d sentences", maxMikrotikSentences)) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHmReadSentenceDeadlineError(t *testing.T) {
	// A closed net.Pipe rejects SetReadDeadline with io.ErrClosedPipe.
	server, client := net.Pipe()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	c := &mikrotikClient{conn: client}
	_, err := c.readSentence()
	if err == nil {
		t.Fatal("expected SetReadDeadline error")
	}
	if !strings.Contains(err.Error(), "set read deadline") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHmCheckedMikrotikLength(t *testing.T) {
	got, err := checkedMikrotikLength(0xFFFFFFFF)
	if err != nil {
		t.Fatalf("in-range length rejected: %v", err)
	}
	if got != 0xFFFFFFFF {
		t.Fatalf("got %d, want %d", got, 0xFFFFFFFF)
	}

	if _, err := checkedMikrotikLength(^uint64(0)); err == nil {
		t.Fatal("expected overflow error")
	} else if !strings.Contains(err.Error(), "overflows int") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// hmTBlockingConn blocks reads until Close is called.
type hmTBlockingConn struct {
	closed chan struct{}
	once   sync.Once
}

func (c *hmTBlockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *hmTBlockingConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *hmTBlockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestHmExecuteMikrotikJobClosesConnOnContextCancel(t *testing.T) {
	conn := &hmTBlockingConn{closed: make(chan struct{})}

	origDial := mikrotikDial
	defer func() { mikrotikDial = origDial }()
	mikrotikDial = func(context.Context, string, uint32, string, string, bool) (*mikrotikClient, error) {
		return &mikrotikClient{conn: conn}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Unbuffered and unread: sendResult drops the result once ctx is done.
	out := make(resultQueue)
	// Reads block forever unless context.AfterFunc closes the connection, so
	// returning at all proves the cancellation hook fired.
	executeMikrotikJob(ctx, &pb.AgentJob{
		JobId:            "m-cancel",
		DeviceId:         "dev-1",
		MikrotikDevice:   &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		MikrotikCommands: []*pb.MikrotikCommand{{Command: "/interface/print"}},
	}, out)

	select {
	case <-conn.closed:
	default:
		t.Fatal("connection was not closed on context cancellation")
	}
}

func TestHmExecuteMikrotikJobDeliversSentences(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(encodeSentence([]string{"!re", "=name=ether1", "=mtu=1500"}))
	stream.Write(encodeSentence([]string{"!done"}))

	origDial := mikrotikDial
	defer func() { mikrotikDial = origDial }()
	mikrotikDial = func(context.Context, string, uint32, string, string, bool) (*mikrotikClient, error) {
		return &mikrotikClient{conn: &nopCloser{readWriter: &stream}}, nil
	}

	out := make(resultQueue, 1)
	executeMikrotikJob(context.Background(), &pb.AgentJob{
		JobId:            "m-ok",
		DeviceId:         "dev-1",
		MikrotikDevice:   &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		MikrotikCommands: []*pb.MikrotikCommand{{Command: "/interface/print"}},
	}, out)

	o := <-out
	if o.event != "mikrotik_result" {
		t.Fatalf("event = %q, want mikrotik_result", o.event)
	}
	result, ok := o.msg.(*pb.MikrotikResult)
	if !ok {
		t.Fatalf("message type = %T, want *pb.MikrotikResult", o.msg)
	}
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if len(result.Sentences) != 1 {
		t.Fatalf("expected 1 sentence, got %d", len(result.Sentences))
	}
	if got := result.Sentences[0].Attributes["name"]; got != "ether1" {
		t.Fatalf("expected name=ether1, got %q", got)
	}
	if got := result.Sentences[0].Attributes["mtu"]; got != "1500" {
		t.Fatalf("expected mtu=1500, got %q", got)
	}
	if result.JobId != "m-ok" || result.DeviceId != "dev-1" {
		t.Fatalf("unexpected identity: %+v", result)
	}
}

func TestPropHmEncodeLengthRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 0x0FFFFFFF).Draw(t, "n")
		enc := encodeLength(n)
		c := &mikrotikClient{conn: &nopCloser{readWriter: bytes.NewBuffer(enc)}}
		got, err := c.readLength()
		if err != nil {
			t.Fatalf("readLength(%#v) for n=%d: %v", enc, n, err)
		}
		if got != n {
			t.Fatalf("roundtrip mismatch: encoded %d as %#v, decoded %d", n, enc, got)
		}
	})
}

func TestPropHmEncodeLengthPrefixFree(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 0x7FFFFFFF).Draw(t, "n")
		enc := encodeLength(n)

		var wantLen int
		var wantMask, wantBits byte
		switch {
		case n < 0x80:
			wantLen, wantMask, wantBits = 1, 0x80, 0x00
		case n < 0x4000:
			wantLen, wantMask, wantBits = 2, 0xC0, 0x80
		case n < 0x200000:
			wantLen, wantMask, wantBits = 3, 0xE0, 0xC0
		case n < 0x10000000:
			wantLen, wantMask, wantBits = 4, 0xF0, 0xE0
		default:
			wantLen, wantMask, wantBits = 5, 0xFF, 0xF0
		}

		if len(enc) != wantLen {
			t.Fatalf("encodeLength(%d) = %#v, want %d bytes", n, enc, wantLen)
		}
		if enc[0]&wantMask != wantBits {
			t.Fatalf("encodeLength(%d) first byte %#x does not match tier bits %#x/%#x", n, enc[0], wantBits, wantMask)
		}
	})
}

func TestPropHmParseMikrotikAttrs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		attrs := rapid.MapOf(
			rapid.StringMatching(`[a-zA-Z0-9._\-]{1,12}`),
			rapid.StringN(0, 12, 24),
		).Draw(t, "attrs")

		words := make([]string, 0, len(attrs))
		for k, v := range attrs {
			words = append(words, "="+k+"="+v)
		}

		got := parseMikrotikAttrs(words)
		if !maps.Equal(got, attrs) {
			t.Fatalf("parseMikrotikAttrs(%q) = %v, want %v", words, got, attrs)
		}

		// Words without the leading "=" carry no attribute.
		bare := make([]string, 0, len(words))
		for _, w := range words {
			bare = append(bare, strings.TrimPrefix(w, "="))
		}
		if skipped := parseMikrotikAttrs(bare); len(skipped) != 0 {
			t.Fatalf("expected words without '=' prefix to be skipped, got %v", skipped)
		}
	})
}

func TestPropHmWriteSentenceRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// An empty word terminates a sentence, so words must be non-empty.
		words := rapid.SliceOfN(rapid.StringN(1, 24, 48), 0, 16).Draw(t, "words")

		var buf bytes.Buffer
		c := &mikrotikClient{conn: &nopCloser{readWriter: &buf}}
		if err := c.writeSentence(words); err != nil {
			t.Fatalf("writeSentence(%q): %v", words, err)
		}

		got, err := c.readSentence()
		if err != nil {
			t.Fatalf("readSentence after writeSentence(%q): %v", words, err)
		}
		if !slices.Equal(got, words) {
			t.Fatalf("roundtrip mismatch: wrote %q, read %q", words, got)
		}
	})
}
