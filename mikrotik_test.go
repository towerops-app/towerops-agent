package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
)

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
		defer serverW.Close()
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
		defer serverW.Close()
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

func TestMikrotikClose(t *testing.T) {
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()

	conn := &readWriteCloser{r: clientR, w: clientW}
	c := &mikrotikClient{conn: conn}

	var receivedWords []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverW.Close()
		sc := &mikrotikClient{conn: &readWriteCloser{r: serverR, w: serverW}}
		receivedWords, _ = sc.readSentence()
		_ = sc.writeSentence([]string{"!fatal"})
	}()

	_ = c.close()
	<-done

	if len(receivedWords) == 0 || receivedWords[0] != "/quit" {
		t.Errorf("expected /quit command, got: %v", receivedWords)
	}
}

func TestMikrotikConnect(t *testing.T) {
	// Start a test TCP server that speaks mikrotik binary protocol
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
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
	fmt.Sscanf(port, "%d", &portNum)

	client, err := mikrotikConnect("127.0.0.1", portNum, "admin", "pass", false)
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
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := &mikrotikClient{conn: conn}
		_, _ = sc.readSentence()
		// Respond with trap error + done
		_ = sc.writeSentence([]string{"!trap", "=message=invalid user"})
		_ = sc.writeSentence([]string{"!done"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	fmt.Sscanf(port, "%d", &portNum)

	_, err = mikrotikConnect("127.0.0.1", portNum, "admin", "wrong", false)
	if err == nil {
		t.Error("expected auth error")
	}
}

func TestMikrotikConnectFatalError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := &mikrotikClient{conn: conn}
		_, _ = sc.readSentence()
		// Respond with fatal error
		_ = sc.writeSentence([]string{"!fatal", "=message=connection reset"})
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint32
	fmt.Sscanf(port, "%d", &portNum)

	_, err = mikrotikConnect("127.0.0.1", portNum, "admin", "pass", false)
	if err == nil {
		t.Error("expected fatal error")
	}
}

func TestMikrotikConnectRefused(t *testing.T) {
	// Connect to a port with nothing listening
	_, err := mikrotikConnect("127.0.0.1", 1, "admin", "pass", false)
	if err == nil {
		t.Error("expected connection refused")
	}
}

func TestMikrotikConnectSSL(t *testing.T) {
	// SSL connect to a port with nothing listening — tests the TLS dialer path
	_, err := mikrotikConnect("127.0.0.1", 1, "admin", "pass", true)
	if err == nil {
		t.Error("expected connection error with SSL")
	}
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
	defer server.Close()
	defer client.Close()

	go func() {
		server.Write(encodeSentence([]string{"!done"}))
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
