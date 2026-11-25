// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

func TestExecutePingJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		out := newResultQueue(1)
		executePingJob(context.Background(), &pb.AgentJob{JobId: "p1"}, out)
		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "failure" {
			t.Errorf("expected failure status for nil device, got: %s", result.Status)
		}
	})

	t.Run("success uses configured timeout", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		var gotTimeoutMs []int
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			gotTimeoutMs = append(gotTimeoutMs, timeoutMs)
			return 3.14, nil
		}

		out := newResultQueue(1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:         "p1",
			DeviceId:      "dev-1",
			SnmpDevice:    &pb.SnmpDevice{Ip: "10.0.0.1"},
			PingTimeoutMs: 1_234,
		}, out)

		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "success" {
			t.Errorf("status: got %q, want %q", result.Status, "success")
		}
		if result.ResponseTimeMs != 3.14 {
			t.Errorf("response time: got %v, want 3.14", result.ResponseTimeMs)
		}
		if result.DeviceId != "dev-1" {
			t.Errorf("device id: got %q, want %q", result.DeviceId, "dev-1")
		}
		if result.PacketLossPercent != 0 {
			t.Errorf("packet loss: got %v, want 0", result.PacketLossPercent)
		}
		// The job's timeout budgets the whole round; each of the three
		// probes gets an equal share so all timeouts end inside it.
		if len(gotTimeoutMs) != pingProbeCount {
			t.Fatalf("probe count: got %d, want %d", len(gotTimeoutMs), pingProbeCount)
		}
		for i, tm := range gotTimeoutMs {
			if tm != 1_234/pingProbeCount {
				t.Errorf("probe %d timeout: got %dms, want %dms", i, tm, 1_234/pingProbeCount)
			}
		}
	})

	t.Run("small timeout keeps each probe at least 1ms", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		var gotTimeoutMs []int
		doPing = func(_ context.Context, _ string, timeoutMs int) (float64, error) {
			gotTimeoutMs = append(gotTimeoutMs, timeoutMs)
			return 3.14, nil
		}

		out := newResultQueue(1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:         "p-small-timeout",
			DeviceId:      "dev-small-timeout",
			SnmpDevice:    &pb.SnmpDevice{Ip: "10.0.0.2"},
			PingTimeoutMs: 2,
		}, out)
		sshTReceiveMonitoringResult(t, out)

		if len(gotTimeoutMs) != pingProbeCount {
			t.Fatalf("probe count: got %d, want %d", len(gotTimeoutMs), pingProbeCount)
		}
		for i, timeoutMs := range gotTimeoutMs {
			if timeoutMs != 1 {
				t.Errorf("probe %d timeout: got %dms, want 1ms", i, timeoutMs)
			}
		}
	})

	t.Run("failure uses default timeout for legacy jobs", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		var gotTimeoutMs []int
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			gotTimeoutMs = append(gotTimeoutMs, timeoutMs)
			return 0, fmt.Errorf("request timeout")
		}

		out := newResultQueue(1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:      "p2",
			DeviceId:   "dev-2",
			SnmpDevice: &pb.SnmpDevice{Ip: "192.168.1.1"},
		}, out)

		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "failure" {
			t.Errorf("status: got %q, want %q", result.Status, "failure")
		}
		if result.PacketLossPercent != 100 {
			t.Errorf("packet loss: got %v, want 100 for a dead target", result.PacketLossPercent)
		}
		if len(gotTimeoutMs) != pingProbeCount {
			t.Fatalf("probe count: got %d, want %d", len(gotTimeoutMs), pingProbeCount)
		}
		for i, tm := range gotTimeoutMs {
			if tm != defaultPingTimeoutMs/pingProbeCount {
				t.Errorf("probe %d timeout: got %dms, want %dms",
					i, tm, defaultPingTimeoutMs/pingProbeCount)
			}
		}
	})

	t.Run("partial loss still reports success with the share that answered", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		calls := 0
		doPing = func(_ context.Context, ip string, _ int) (float64, error) {
			calls++
			if calls == 2 {
				return 0, fmt.Errorf("request timeout")
			}
			return 4.4, nil
		}

		out := newResultQueue(1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:      "p3",
			DeviceId:   "dev-3",
			SnmpDevice: &pb.SnmpDevice{Ip: "192.168.1.2"},
		}, out)

		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "success" {
			t.Errorf("status: got %q, want %q (a reply is a reply)", result.Status, "success")
		}
		wantLoss := float64(pingProbeCount-2) * 100.0 / float64(pingProbeCount)
		if result.PacketLossPercent != wantLoss {
			t.Errorf("packet loss: got %v, want %v (1 of %d probes lost)",
				result.PacketLossPercent, wantLoss, pingProbeCount)
		}
	})
}

func sshTReceiveMonitoringResult(t *testing.T, out *resultQueue) *pb.MonitoringCheck {
	t.Helper()
	select {
	case queued := <-out.items:
		if queued.event != "monitoring_check" {
			t.Fatalf("event = %q, want monitoring_check", queued.event)
		}
		return decodeQueuedResult[*pb.MonitoringCheck](t, queued)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for monitoring result")
		return nil
	}
}

func sshTReceiveMikrotikResult(t *testing.T, out *resultQueue) *pb.MikrotikResult {
	t.Helper()
	select {
	case queued := <-out.items:
		if queued.event != "mikrotik_result" {
			t.Fatalf("event = %q, want mikrotik_result", queued.event)
		}
		return decodeQueuedResult[*pb.MikrotikResult](t, queued)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MikroTik result")
		return nil
	}
}

func TestExecuteMikrotikJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		out := newResultQueue(1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{JobId: "m1"}, out)
		result := sshTReceiveMikrotikResult(t, out)
		if result.Error == "" {
			t.Error("expected error for nil device")
		}
		if !strings.Contains(result.Error, "missing device") {
			t.Errorf("expected 'missing device' in error, got: %s", result.Error)
		}
	})

	t.Run("dial error", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()
		mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return nil, fmt.Errorf("connection refused")
		}

		out := newResultQueue(1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{
			JobId:          "m1",
			DeviceId:       "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}, out)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error == "" {
			t.Error("expected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()

		mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{resp: &mikrotikResponse{sentences: []mikrotikSentence{{attributes: map[string]string{"name": "ether1"}}}}},
				{resp: &mikrotikResponse{}}, // close /quit
			}), nil
		}

		out := newResultQueue(1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{
			JobId:    "m1",
			DeviceId: "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{
				Ip: "10.0.0.1", Port: 8728, Username: "admin", Password: "pass",
			},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/interface/print"},
			},
		}, out)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error != "" {
			t.Errorf("unexpected error: %s", result.Error)
		}
		if len(result.Sentences) != 1 {
			t.Fatalf("got %d sentences, want 1", len(result.Sentences))
		}
		if result.Sentences[0].Attributes["name"] != "ether1" {
			t.Errorf("expected name=ether1, got %v", result.Sentences[0].Attributes)
		}
	})

	t.Run("command error", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()

		mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{err: fmt.Errorf("fatal: connection lost")},
				{resp: &mikrotikResponse{}}, // close
			}), nil
		}

		out := newResultQueue(1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{
			JobId:          "m1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/system/reboot"},
			},
		}, out)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error == "" {
			t.Error("expected error from failed command")
		}
	})

	t.Run("response error", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()

		mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{resp: &mikrotikResponse{err: "no such command"}},
				{resp: &mikrotikResponse{}}, // close
			}), nil
		}

		out := newResultQueue(1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{
			JobId:          "m1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/bad/command"},
			},
		}, out)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error == "" {
			t.Error("expected error from response error")
		}
	})

}

func resetHostKeyStore(t *testing.T) {
	t.Helper()
	original := globalHostKeys
	t.Cleanup(func() { globalHostKeys = original })
	globalHostKeys = newHostKeyStore(filepath.Join(t.TempDir(), "hosts.json"))
}

func startTestSSHServer(t *testing.T, handler func(ch ssh.Channel)) (string, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return startTestSSHServerWithSigner(t, signer, func(ch ssh.Channel, _ string) { handler(ch) })
}

// startTestSSHServerWithSigner is startTestSSHServer with a caller-supplied
// host key; the handler additionally receives the exec command so tests can
// dispatch per command across the job's multiple sessions.
func startTestSSHServerWithSigner(
	t *testing.T,
	signer ssh.Signer,
	handler func(ch ssh.Channel, command string),
) (string, func()) {
	t.Helper()

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil // Accept any password
		},
	}
	config.AddHostKey(signer)

	return startTestSSHServerWithConfig(t, config, handler)
}

// startTestSSHServerWithConfig is startTestSSHServerWithSigner with a
// caller-owned ServerConfig, for tests that need to narrow the algorithm
// set (e.g. to the legacy algorithms an old RouterOS 6 server offers).
func startTestSSHServerWithConfig(
	t *testing.T,
	config *ssh.ServerConfig,
	handler func(ch ssh.Channel, command string),
) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()

				sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.Type == "exec" {
								_ = req.Reply(true, nil)
								handler(ch, string(req.Payload[4:]))
								return
							}
							_ = req.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

// mockMikrotikResponse pairs a response with an optional error for mock execute calls.
type mockMikrotikResponse struct {
	resp *mikrotikResponse
	err  error
}

// newMockMikrotikClient creates a mikrotikClient backed by a mock that returns
// canned responses from the provided list, in order.
func newMockMikrotikClient(responses []mockMikrotikResponse) *mikrotikClient {
	return &mikrotikClient{conn: &mockMikrotikConn{responses: responses}}
}

// mockMikrotikConn is a fake io.ReadWriteCloser that the mikrotikClient can use.
// It intercepts execute() calls by providing pre-encoded binary responses.
// Since mikrotikClient.execute calls writeSentence then readResponse, we need
// a conn that absorbs writes and returns pre-built binary sentences on read.
type mockMikrotikConn struct {
	responses []mockMikrotikResponse
	callIdx   int
	readBuf   []byte
}

func (m *mockMikrotikConn) Write(p []byte) (int, error) {
	// Absorb writes (the command sentence). When a full sentence is written,
	// prepare the response for the next read.
	// We detect sentence end by looking for the 0x00 terminator.
	for _, b := range p {
		if b == 0x00 {
			// A sentence was completed. Prepare the response.
			if m.callIdx < len(m.responses) {
				r := m.responses[m.callIdx]
				m.callIdx++
				if r.err != nil {
					// Encode a !fatal response
					m.readBuf = append(m.readBuf, encodeSentence([]string{"!fatal", "=message=" + r.err.Error()})...)
				} else {
					// Encode sentences
					for _, s := range r.resp.sentences {
						words := []string{"!re"}
						for k, v := range s.attributes {
							words = append(words, "="+k+"="+v)
						}
						m.readBuf = append(m.readBuf, encodeSentence(words)...)
					}
					if r.resp.err != "" {
						m.readBuf = append(m.readBuf, encodeSentence([]string{"!trap", "=message=" + r.resp.err})...)
					}
					m.readBuf = append(m.readBuf, encodeSentence([]string{"!done"})...)
				}
			}
		}
	}
	return len(p), nil
}

func (m *mockMikrotikConn) Read(p []byte) (int, error) {
	if len(m.readBuf) == 0 {
		return 0, fmt.Errorf("no data")
	}
	n := copy(p, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}

func (m *mockMikrotikConn) Close() error { return nil }

// chkTOrigSSHDial captures the production sshDial implementation before any
// test can replace it.
var chkTOrigSSHDial = sshDial

func TestChkTSSHDialHandshakeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Accept the TCP connection, then speak something that is not an SSH
	// banner so ssh.NewClientConn fails after the dial succeeded.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("chkT not an ssh server\r\n"))
		_ = conn.Close()
	}()

	client, err := chkTOrigSSHDial(context.Background(), "tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected the SSH handshake to fail against a non-SSH server")
	}
	if client != nil {
		t.Fatalf("expected a nil client on handshake failure, got %v", client)
	}
}

func TestChkTSSHDialConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	client, err := chkTOrigSSHDial(context.Background(), "tcp", addr, &ssh.ClientConfig{
		User:            "admin",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected a dial failure against a closed port")
	}
	if client != nil {
		t.Fatalf("expected a nil client on dial failure, got %v", client)
	}
}

func startDroppingSSHServer(t *testing.T, output string) (string, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					ch, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.Type == "exec" {
								_ = req.Reply(true, nil)
								_, _ = ch.Write([]byte(output))
								// Drop the transport instead of closing the
								// channel: the client sees a channel that
								// ended without an exit status over a dead
								// connection.
								_ = sconn.Close()
								return
							}
							_ = req.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestSSHResolveRejectsMissingPort(t *testing.T) {
	if _, err := sshResolve(context.Background(), "10.0.0.1"); err == nil {
		t.Fatal("an address without a port must be rejected")
	}
}

// TestSSHResolveReportsLookupFailure: a hostname (not a literal) routes
// through the resolver's context select, so an already-canceled context —
// like the .invalid name that never resolves — must surface as an error,
// never as an empty result.
func TestSSHResolveReportsLookupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sshResolve(ctx, "towerops-coverage.invalid:22"); err == nil {
		t.Fatal("a failed lookup must be reported")
	}
}

func TestHostKeyAlgorithmsFor(t *testing.T) {
	tests := map[string][]string{
		ssh.KeyAlgoRSA:         {ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA},
		ssh.CertAlgoRSAv01:     {ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01},
		ssh.KeyAlgoED25519:     {ssh.KeyAlgoED25519},
		ssh.KeyAlgoECDSA256:    {ssh.KeyAlgoECDSA256},
		ssh.CertAlgoED25519v01: {ssh.CertAlgoED25519v01},
	}
	for keyType, want := range tests {
		if got := hostKeyAlgorithmsFor(keyType); !slices.Equal(got, want) {
			t.Errorf("hostKeyAlgorithmsFor(%q) = %v, want %v", keyType, got, want)
		}
	}
}

// --- Fake shell device -------------------------------------------------
//
// A scripted SSH server that accepts pty-req + shell, prints a banner and
// prompt, then answers each input line from a per-test script map. Replies
// may contain pager pauses (the pager answer is dispatched as the line "
// "), ANSI colors, bare-\r redraws, wrapped echoes and mode-changing
// prompts — everything the expect engine has to survive.

// shellReply is one scripted response: echo overrides the echoed input
// line (for wrapped echoes); lines are written after the echo.
type shellReply struct {
	echo  string
	lines []string
}

// shellScript maps input lines to replies. The pager answer arrives as the
// line " "; a bare newline is "".
type shellScript map[string]shellReply

// fakeShellServer is a running fake shell device plus what tests assert on.
type fakeShellServer struct {
	addr    string
	cleanup func()

	mu       sync.Mutex
	received []string
}

// receivedLines snapshots every input line the device processed.
func (f *fakeShellServer) receivedLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

// startFakeShellServer serves one shell per connection with the given
// banner and prompt, dispatching input lines to script.
func startFakeShellServer(t *testing.T, banner, prompt string, script shellScript) *fakeShellServer {
	t.Helper()

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(cbNewSigner(t))

	return startFakeShellServerWithConfig(t, config, banner, prompt, script)
}

// startFakeShellServerWithConfig is startFakeShellServer with a caller
// owned ServerConfig, for auth tests.
func startFakeShellServerWithConfig(
	t *testing.T,
	config *ssh.ServerConfig,
	banner, prompt string,
	script shellScript,
) *fakeShellServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeShellServer{addr: ln.Addr().String()}

	// writeFrag writes s as a terminal fragment: embedded newlines become
	// CRLF, but the text is not terminated — exactly how devices write a
	// prompt or the final line of a reply.
	writeFrag := func(ch ssh.Channel, s string) {
		_, _ = io.WriteString(ch, strings.ReplaceAll(s, "\n", "\r\n"))
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()

				sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}

					handleLine := func(line string, echo bool) {
						fake.mu.Lock()
						fake.received = append(fake.received, line)
						fake.mu.Unlock()
						if line == "exit" {
							_ = ch.Close()
							return
						}
						reply := script[line]
						switch {
						case reply.echo != "":
							writeFrag(ch, reply.echo+"\n")
						case echo && line != "":
							// The device echoes the command as typed; pager
							// keystrokes are consumed, not echoed.
							writeFrag(ch, line+"\n")
						}
						for i, l := range reply.lines {
							if i < len(reply.lines)-1 {
								writeFrag(ch, l+"\n")
							} else {
								writeFrag(ch, l) // last line is a fragment
							}
						}
						if len(reply.lines) == 0 && (line == "" || line == " ") {
							// Bare newline or unanswered pager: prompt only.
							writeFrag(ch, prompt)
						}
					}

					var shellStarted atomic.Bool
					var lineBuf []byte
					go func() {
						defer func() { _ = ch.Close() }()
						readBuf := make([]byte, 512)
						for {
							n, err := ch.Read(readBuf)
							for _, b := range readBuf[:n] {
								if !shellStarted.Load() {
									continue
								}
								switch b {
								case '\n':
								case '\r':
									handleLine(string(lineBuf), true)
									lineBuf = lineBuf[:0]
								default:
									lineBuf = append(lineBuf, b)
									// Single-character script keys (" ", "q",
									// "y", …) are pager and prompt answers the
									// device reads without a newline: dispatch
									// them the moment they arrive. Multi-character
									// keys wait for the terminator.
									if len(lineBuf) == 1 {
										if _, ok := script[string(lineBuf)]; ok {
											handleLine(string(lineBuf), false)
											lineBuf = lineBuf[:0]
										}
									}
								}
							}
							if err != nil {
								return
							}
						}
					}()

					for req := range requests {
						switch req.Type {
						case "pty-req":
							_ = req.Reply(true, nil)
						case "shell":
							_ = req.Reply(true, nil)
							shellStarted.Store(true)
							writeFrag(ch, banner+prompt)
						default:
							_ = req.Reply(false, nil)
						}
					}
				}
			}()
		}
	}()

	fake.cleanup = func() { _ = ln.Close() }
	return fake
}

// TestSSHDialCancelDuringHandshakeClosesConnection covers the context
// AfterFunc inside the real sshDial: a cancellation landing mid-handshake
// closes the TCP connection, which is what unwinds a stalled server.
func TestSSHDialCancelDuringHandshakeClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Accept the TCP connection but never speak the SSH banner, so the
	// handshake blocks inside ssh.NewClientConn until the AfterFunc close.
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		client, err := chkTOrigSSHDial(ctx, "tcp", ln.Addr().String(), &ssh.ClientConfig{
			User:            "admin",
			Auth:            []ssh.AuthMethod{ssh.Password("secret")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if client != nil {
			_ = client.Close()
		}
		dialed <- err
	}()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("dial never reached the server")
	}
	cancel()

	select {
	case err := <-dialed:
		if err == nil {
			t.Fatal("dial succeeded after its context was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the dial context did not unwind the handshake")
	}

	// The AfterFunc closes the TCP connection: server-side reads drain the
	// client's banner and then hit EOF.
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	var rerr error
	for rerr == nil {
		_, rerr = serverConn.Read(buf)
	}
	_ = serverConn.Close()
}
