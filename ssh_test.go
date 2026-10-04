// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
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
		var gotTimeoutMs int
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			gotTimeoutMs = timeoutMs
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
		if gotTimeoutMs != 1_234 {
			t.Errorf("timeout: got %dms, want 1234ms", gotTimeoutMs)
		}
	})

	t.Run("failure uses default timeout for legacy jobs", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		var gotTimeoutMs int
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			gotTimeoutMs = timeoutMs
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
		if gotTimeoutMs != defaultPingTimeoutMs {
			t.Errorf("timeout: got %dms, want default %dms", gotTimeoutMs, defaultPingTimeoutMs)
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
	case <-time.After(time.Second):
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

	t.Run("backup routing via SSH", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
			return "/ip address\nadd address=10.0.0.1/24", nil
		}

		out := newResultQueue(1)
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

		out := newResultQueue(1)
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

		out := newResultQueue(1)
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

		out := newResultQueue(1)
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

// TestExecuteMikrotikBackupNoExitStatus covers RouterOS 6: its SSH server
// closes the exec channel without an exit-status, which session.Run reports
// as *ssh.ExitMissingError. The output is still complete and the backup must
// be returned, not rejected.
func TestExecuteMikrotikBackupNoExitStatus(t *testing.T) {
	resetHostKeyStore(t)

	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("# RouterOS config\n/ip address\nadd address=10.0.0.1/24\n"))
		_ = ch.CloseWrite()
		_ = ch.Close() // no exit-status: what ROS 6 sends
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	config, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err != nil {
		t.Fatalf("RouterOS 6 export must not fail on a missing exit-status: %v", err)
	}
	if !strings.Contains(config, "add address=10.0.0.1/24") {
		t.Errorf("expected export content, got: %q", config)
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

func TestLegacySSHBackupRejectsInvalidExport(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		stderr string
		want   string
	}{
		{"stdout failure", "# partial config\nfailure: export interrupted\n", "", "failure: export interrupted"},
		{"stderr failure", "# partial config", "not enough permissions (9)\n", "not enough permissions"},
		{"empty export", "", "", "EXPORT_EMPTY"},
		{"diagnostic only", "export interrupted\n", "", "EXPORT_INCOMPLETE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetHostKeyStore(t)
			addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
				defer func() { _ = ch.Close() }()
				if _, err := io.WriteString(ch, tt.stdout); err != nil {
					t.Errorf("write stdout: %v", err)
					return
				}
				if _, err := io.WriteString(ch.Stderr(), tt.stderr); err != nil {
					t.Errorf("write stderr: %v", err)
					return
				}
				if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
					t.Errorf("send exit status: %v", err)
				}
			})
			defer cleanup()
			host, port := cbAddrPort(t, addr)
			config, err := executeMikrotikBackupContext(context.Background(), host, uint16(port), "admin", "pass")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("backup = %q, error = %v; want failure containing %q", config, err, tt.want)
			}
		})
	}
}

func TestLegacySSHBackupPreservesConfigWithFailureComments(t *testing.T) {
	resetHostKeyStore(t)
	want := "# failure: text in a comment\n/system identity\nset name=router\n"
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		defer func() { _ = ch.Close() }()
		if _, err := io.WriteString(ch, want); err != nil {
			t.Errorf("write export: %v", err)
			return
		}
		if _, err := io.WriteString(ch.Stderr(), "warning: device busy\n"); err != nil {
			t.Errorf("write stderr: %v", err)
			return
		}
		if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Errorf("send exit status: %v", err)
		}
	})
	defer cleanup()
	host, port := cbAddrPort(t, addr)
	config, err := executeMikrotikBackupContext(context.Background(), host, uint16(port), "admin", "pass")
	if err != nil || config != want {
		t.Fatalf("backup = %q, error = %v; want %q", config, err, want)
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

// TestSSHBackupPinsStoredHostKeyAlgorithm: once an endpoint has a typed TOFU
// entry, executeMikrotikBackupContext must restrict HostKeyAlgorithms to the
// pinned key type so a reordering of x/crypto's preference list cannot make a
// dual-key device present a different key and trip a false MITM error.
func TestSSHBackupPinsStoredHostKeyAlgorithm(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("# RouterOS config\n"))
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	origDial := sshDial
	defer func() { sshDial = origDial }()
	var captured *ssh.ClientConfig
	sshDial = func(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		captured = config
		return chkTOrigSSHDial(ctx, network, addr, config)
	}

	// First connect trusts on first use; nothing pinned yet. HostKeyAlgorithms
	// stays unset so x/crypto's default preference order applies — the widened
	// set only appends missing KEX/ciphers (routerOSSSHAlgorithms).
	if _, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass"); err != nil {
		t.Fatalf("first connect failed: %v", err)
	}
	if len(captured.HostKeyAlgorithms) != 0 {
		t.Fatalf("first-use HostKeyAlgorithms = %v, want unset", captured.HostKeyAlgorithms)
	}
	var defaults ssh.Config
	defaults.SetDefaults()
	if want := mergeAlgorithms(defaults.KeyExchanges, ssh.InsecureAlgorithms().KeyExchanges, ssh.SupportedAlgorithms().KeyExchanges); !slices.Equal(captured.KeyExchanges, want) {
		t.Fatalf("first-use KeyExchanges = %v, want %v", captured.KeyExchanges, want)
	}

	// Second connect offers only the pinned key type.
	captured = nil
	if _, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass"); err != nil {
		t.Fatalf("pinned connect failed: %v", err)
	}
	if len(captured.HostKeyAlgorithms) != 1 || captured.HostKeyAlgorithms[0] != ssh.KeyAlgoECDSA256 {
		t.Fatalf("pinned HostKeyAlgorithms = %v, want [%s]", captured.HostKeyAlgorithms, ssh.KeyAlgoECDSA256)
	}

	// An endpoint with no entry is unpinned. A closed port on 127.0.0.1 —
	// not 127.0.0.2, which macOS never refuses — keeps the connect instant.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := dead.Addr().(*net.TCPAddr).Port
	_ = dead.Close()
	if _, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", uint16(deadPort), "admin", "pass"); err == nil {
		t.Fatal("dial to a closed port should fail")
	}
	if len(captured.HostKeyAlgorithms) != 0 {
		t.Fatalf("unpinned HostKeyAlgorithms = %v, want unset", captured.HostKeyAlgorithms)
	}
}

// TestSSHBackupPinnedAlgorithmRejectsOtherKeyTypes proves the pin is active:
// an RSA pin against an ecdsa-only server must fail the handshake with "no
// common algorithm", not merely a host key mismatch.
func TestSSHBackupPinnedAlgorithmRejectsOtherKeyTypes(t *testing.T) {
	resetHostKeyStore(t)
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) { _ = ch.Close() })
	defer cleanup()

	globalHostKeys.keys["ssh:"+addr] = storedHostKeyEntry(strings.Repeat("ab", 32), ssh.KeyAlgoRSA)

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if err == nil {
		t.Fatal("connect succeeded despite an RSA-only pin against an ecdsa server")
	}
	if !strings.Contains(err.Error(), "no common algorithm") {
		t.Fatalf("err = %v, want a host-key-algorithm negotiation failure", err)
	}
}

// TestSSHBackupOutputBounded: a device that streams more than the cap must be
// cut off with errConfigBackupTooLarge while retaining only the capped prefix.
func TestSSHBackupOutputBounded(t *testing.T) {
	resetHostKeyStore(t)
	orig := sshBackupMaxOutputBytes
	sshBackupMaxOutputBytes = 256
	defer func() { sshBackupMaxOutputBytes = orig }()

	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		chunk := bytes.Repeat([]byte("x"), 4096)
		for range 64 { // 256 KiB of spam past the 256-byte cap
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	_, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass")
	if !errors.Is(err, errConfigBackupTooLarge) {
		t.Fatalf("err = %v, want errConfigBackupTooLarge", err)
	}
}

// TestSSHBackupPinnedRSAOffersSHA2: an RSA pin is stored as "ssh-rsa" (the
// key type), but must still negotiate with a device that has disabled SHA-1
// signatures and only signs rsa-sha2-256/512.
func TestSSHBackupPinnedRSAOffersSHA2(t *testing.T) {
	resetHostKeyStore(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerWithAlgorithms(base.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA256})
	if err != nil {
		t.Fatal(err)
	}
	addr, cleanup := startTestSSHServerWithSigner(t, signer, func(ch ssh.Channel, _ string) {
		_, _ = ch.Write([]byte("# RouterOS config\n"))
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	// First use pins the RSA key, then the pinned reconnect must succeed.
	for i := 0; i < 2; i++ {
		if _, err := executeMikrotikBackupContext(context.Background(), "127.0.0.1", portNum, "admin", "pass"); err != nil {
			t.Fatalf("connect %d failed: %v", i, err)
		}
	}
	if got := globalHostKeys.pinnedKeyAlgorithm("ssh:" + addr); got != ssh.KeyAlgoRSA {
		t.Fatalf("pinned type = %q, want %q", got, ssh.KeyAlgoRSA)
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
