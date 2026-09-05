// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

func TestExecutePingJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		out := make(resultQueue, 1)
		executePingJob(context.Background(), &pb.AgentJob{JobId: "p1"}, out)
		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "failure" {
			t.Errorf("expected failure status for nil device, got: %s", result.Status)
		}
	})

	t.Run("success", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			return 3.14, nil
		}

		out := make(resultQueue, 1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:      "p1",
			DeviceId:   "dev-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
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
	})

	t.Run("failure", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			return 0, fmt.Errorf("request timeout")
		}

		out := make(resultQueue, 1)
		executePingJob(context.Background(), &pb.AgentJob{
			JobId:      "p2",
			DeviceId:   "dev-2",
			SnmpDevice: &pb.SnmpDevice{Ip: "192.168.1.1"},
		}, out)

		result := sshTReceiveMonitoringResult(t, out)
		if result.Status != "failure" {
			t.Errorf("status: got %q, want %q", result.Status, "failure")
		}
	})
}

func sshTReceiveMonitoringResult(t *testing.T, out resultQueue) *pb.MonitoringCheck {
	t.Helper()
	select {
	case queued := <-out:
		if queued.event != "monitoring_check" {
			t.Fatalf("event = %q, want monitoring_check", queued.event)
		}
		result, ok := queued.msg.(*pb.MonitoringCheck)
		if !ok {
			t.Fatalf("message type = %T, want *pb.MonitoringCheck", queued.msg)
		}
		return result
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for monitoring result")
		return nil
	}
}

func sshTReceiveMikrotikResult(t *testing.T, out resultQueue) *pb.MikrotikResult {
	t.Helper()
	select {
	case queued := <-out:
		if queued.event != "mikrotik_result" {
			t.Fatalf("event = %q, want mikrotik_result", queued.event)
		}
		result, ok := queued.msg.(*pb.MikrotikResult)
		if !ok {
			t.Fatalf("message type = %T, want *pb.MikrotikResult", queued.msg)
		}
		return result
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MikroTik result")
		return nil
	}
}

func TestExecuteMikrotikJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		out := make(resultQueue, 1)
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

		out := make(resultQueue, 1)
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

		out := make(resultQueue, 1)
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

		out := make(resultQueue, 1)
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

		out := make(resultQueue, 1)
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

	t.Run("backup routing via SSH", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
			return "/ip address\nadd address=10.0.0.1/24", nil
		}

		out := make(resultQueue, 1)
		executeMikrotikJob(context.Background(), &pb.AgentJob{
			JobId:          "backup:dev1",
			DeviceId:       "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
		}, out)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error != "" {
			t.Errorf("unexpected error: %s", result.Error)
		}
		if len(result.Sentences) != 1 {
			t.Fatalf("got %d sentences, want 1", len(result.Sentences))
		}
		if result.Sentences[0].Attributes["config"] == "" {
			t.Error("expected config in attributes")
		}
	})
}

func TestExecuteMikrotikBackupViaSSH(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
			return "# test config", nil
		}

		out := make(resultQueue, 1)
		executeMikrotikBackupViaSSH(
			context.Background(),
			&pb.AgentJob{JobId: "backup:1", DeviceId: "d1"},
			&pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
			out, 1000,
		)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error != "" {
			t.Errorf("unexpected error: %s", result.Error)
		}
		if len(result.Sentences) != 1 || result.Sentences[0].Attributes["config"] != "# test config" {
			t.Error("expected config sentence")
		}
	})

	t.Run("error", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
			return "", fmt.Errorf("ssh connection refused")
		}

		out := make(resultQueue, 1)
		executeMikrotikBackupViaSSH(
			context.Background(),
			&pb.AgentJob{JobId: "backup:2", DeviceId: "d2"},
			&pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
			out, 1000,
		)

		result := sshTReceiveMikrotikResult(t, out)
		if result.Error == "" {
			t.Error("expected SSH error")
		}
	})

	t.Run("port overflow", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()
		called := false
		sshBackup = func(context.Context, string, uint16, string, string) (string, error) {
			called = true
			return "", nil
		}

		out := make(resultQueue, 1)
		executeMikrotikBackupViaSSH(
			context.Background(),
			&pb.AgentJob{JobId: "backup:3", DeviceId: "d3"},
			&pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 65536},
			out, 1000,
		)
		result := sshTReceiveMikrotikResult(t, out)
		if called || !strings.Contains(result.Error, "invalid SSH port") {
			t.Fatalf("called/error = %v/%q, want validation before dialing", called, result.Error)
		}
	})
}

func TestSSHBackupIPv6Address(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()

	var capturedAddr string
	sshDial = func(_ context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		capturedAddr = addr
		return nil, fmt.Errorf("mock dial")
	}

	_, _ = executeMikrotikBackupContext(context.Background(), "::1", 22, "admin", "pass")

	if capturedAddr != "[::1]:22" {
		t.Errorf("expected [::1]:22, got %q", capturedAddr)
	}
}

func TestSSHBackupIPv4Address(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()

	var capturedAddr string
	sshDial = func(_ context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		capturedAddr = addr
		return nil, fmt.Errorf("mock dial")
	}

	_, _ = executeMikrotikBackupContext(context.Background(), "10.0.0.1", 22, "admin", "pass")

	if capturedAddr != "10.0.0.1:22" {
		t.Errorf("expected 10.0.0.1:22, got %q", capturedAddr)
	}
}

func TestExecuteMikrotikBackupDialError(t *testing.T) {
	_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", 1, "admin", "pass")
	if err == nil {
		t.Error("expected SSH dial error")
	}
}

func TestSSHBackupHonorsContextCancellation(t *testing.T) {
	origDial := sshDial
	defer func() { sshDial = origDial }()
	sshDial = func(ctx context.Context, _, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := executeMikrotikBackupContext(ctx, "127.0.0.1", 22, "admin", "pass")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("backup error = %v, want context cancellation", err)
	}
}

func TestSSHBackupHandshakeTimeout(t *testing.T) {
	origDial := sshDial
	origTimeout := sshBackupTimeout
	defer func() {
		sshDial = origDial
		sshBackupTimeout = origTimeout
	}()
	sshDial = chkTOrigSSHDial
	sshBackupTimeout = 100 * time.Millisecond

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
		_, _ = io.Copy(io.Discard, conn)
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	done := make(chan error, 1)
	go func() {
		_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected stalled SSH handshake to time out")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled SSH handshake did not return promptly")
	}
}

func TestSSHBackupCommandTimeout(t *testing.T) {
	resetHostKeyStore(t)
	origTimeout := sshBackupTimeout
	defer func() { sshBackupTimeout = origTimeout }()
	sshBackupTimeout = 500 * time.Millisecond

	releaseCommand := make(chan struct{})
	addr, cleanup := startTestSSHServer(t, func(ssh.Channel) {
		<-releaseCommand
	})
	defer cleanup()
	defer close(releaseCommand)

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	done := make(chan error, 1)
	go func() {
		_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected stalled SSH command to time out")
		}
		if !strings.Contains(err.Error(), "ssh command") {
			t.Fatalf("backup error = %v, want SSH command error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled SSH command did not return promptly")
	}
}

// resetHostKeyStore resets the global host key store for SSH tests
// to prevent cross-test TOFU contamination from different server keys.
func resetHostKeyStore(t *testing.T) {
	t.Helper()
	original := globalHostKeys
	t.Cleanup(func() { globalHostKeys = original })
	globalHostKeys = newHostKeyStore(filepath.Join(t.TempDir(), "hosts.json"))
}

func TestExecuteMikrotikBackupSuccess(t *testing.T) {
	resetHostKeyStore(t)

	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("# RouterOS config\n/ip address\nadd address=10.0.0.1/24\n"))
		_ = ch.CloseWrite()
		// Send exit-status 0
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	config, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if config == "" {
		t.Error("expected non-empty config")
	}
}

func TestExecuteMikrotikBackupCommandError(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		// Send exit-status 1 with no output (simulates command failure)
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err == nil {
		t.Error("expected error from failed command")
	}
}

func TestExecuteMikrotikBackupWithOutput(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("# partial config\n"))
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err == nil {
		t.Fatal("expected command failure when output is present with non-zero exit status")
	}
	if !strings.Contains(err.Error(), "# partial config") {
		t.Fatalf("expected output to be included in error, got: %v", err)
	}
}

func TestExecuteMikrotikBackupSessionError(t *testing.T) {
	resetHostKeyStore(t)

	// SSH server that accepts connection but rejects all channel requests
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

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

		sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer func() { _ = sconn.Close() }()
		go ssh.DiscardRequests(reqs)

		// Reject all channel requests to trigger NewSession error
		for newChannel := range chans {
			_ = newChannel.Reject(ssh.Prohibited, "no sessions allowed")
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err = executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err == nil {
		t.Error("expected session error")
	}
	if !strings.Contains(err.Error(), "ssh session") {
		t.Errorf("expected 'ssh session' in error, got: %v", err)
	}
}

// startTestSSHServer starts a minimal SSH server for testing and returns its address and cleanup function.
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

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil // Accept any password
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
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
						handler(ch)
						return
					}
					_ = req.Reply(false, nil)
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
