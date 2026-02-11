package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

func TestExecutePingJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(chan *pb.MonitoringCheck, 1)
		executePingJob(&pb.AgentJob{JobId: "p1"}, ch)
		if len(ch) != 0 {
			t.Error("expected no result for nil device")
		}
	})

	t.Run("success", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(ip string, timeoutMs int) (float64, error) {
			return 3.14, nil
		}

		ch := make(chan *pb.MonitoringCheck, 1)
		executePingJob(&pb.AgentJob{
			JobId:      "p1",
			DeviceId:   "dev-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		select {
		case result := <-ch:
			if result.Status != "success" {
				t.Errorf("status: got %q, want %q", result.Status, "success")
			}
			if result.ResponseTimeMs != 3.14 {
				t.Errorf("response time: got %v, want 3.14", result.ResponseTimeMs)
			}
			if result.DeviceId != "dev-1" {
				t.Errorf("device id: got %q, want %q", result.DeviceId, "dev-1")
			}
		case <-time.After(time.Second):
			t.Error("timed out")
		}
	})

	t.Run("failure", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(ip string, timeoutMs int) (float64, error) {
			return 0, fmt.Errorf("request timeout")
		}

		ch := make(chan *pb.MonitoringCheck, 1)
		executePingJob(&pb.AgentJob{
			JobId:      "p2",
			DeviceId:   "dev-2",
			SnmpDevice: &pb.SnmpDevice{Ip: "192.168.1.1"},
		}, ch)

		select {
		case result := <-ch:
			if result.Status != "failure" {
				t.Errorf("status: got %q, want %q", result.Status, "failure")
			}
		case <-time.After(time.Second):
			t.Error("timed out")
		}
	})
}

func TestExecuteMikrotikJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{JobId: "m1"}, ch)
		if len(ch) != 0 {
			t.Error("expected no result for nil device")
		}
	})

	t.Run("dial error", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()
		mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return nil, fmt.Errorf("connection refused")
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{
			JobId:          "m1",
			DeviceId:       "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}, ch)

		result := <-ch
		if result.Error == "" {
			t.Error("expected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()

		mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{resp: &mikrotikResponse{sentences: []mikrotikSentence{{attributes: map[string]string{"name": "ether1"}}}}},
				{resp: &mikrotikResponse{}}, // close /quit
			}), nil
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{
			JobId:    "m1",
			DeviceId: "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{
				Ip: "10.0.0.1", Port: 8728, Username: "admin", Password: "pass",
			},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/interface/print"},
			},
		}, ch)

		result := <-ch
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

		mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{err: fmt.Errorf("fatal: connection lost")},
				{resp: &mikrotikResponse{}}, // close
			}), nil
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{
			JobId:          "m1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/system/reboot"},
			},
		}, ch)

		result := <-ch
		if result.Error == "" {
			t.Error("expected error from failed command")
		}
	})

	t.Run("response error", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()

		mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return newMockMikrotikClient([]mockMikrotikResponse{
				{resp: &mikrotikResponse{err: "no such command"}},
				{resp: &mikrotikResponse{}}, // close
			}), nil
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{
			JobId:          "m1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
			MikrotikCommands: []*pb.MikrotikCommand{
				{Command: "/bad/command"},
			},
		}, ch)

		result := <-ch
		if result.Error == "" {
			t.Error("expected error from response error")
		}
	})

	t.Run("backup routing via SSH", func(t *testing.T) {
		origSSH := sshBackup
		defer func() { sshBackup = origSSH }()

		sshBackup = func(ip string, port uint16, username, password string) (string, error) {
			return "/ip address\nadd address=10.0.0.1/24", nil
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikJob(&pb.AgentJob{
			JobId:          "backup:dev1",
			DeviceId:       "dev-1",
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
		}, ch)

		result := <-ch
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

		sshBackup = func(ip string, port uint16, username, password string) (string, error) {
			return "# test config", nil
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikBackupViaSSH(
			&pb.AgentJob{JobId: "backup:1", DeviceId: "d1"},
			&pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
			ch, 1000,
		)

		result := <-ch
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

		sshBackup = func(ip string, port uint16, username, password string) (string, error) {
			return "", fmt.Errorf("ssh connection refused")
		}

		ch := make(chan *pb.MikrotikResult, 1)
		executeMikrotikBackupViaSSH(
			&pb.AgentJob{JobId: "backup:2", DeviceId: "d2"},
			&pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
			ch, 1000,
		)

		result := <-ch
		if result.Error == "" {
			t.Error("expected SSH error")
		}
	})
}

func TestExecuteMikrotikBackupDialError(t *testing.T) {
	_, err := executeMikrotikBackup("127.0.0.1", 1, "admin", "pass")
	if err == nil {
		t.Error("expected SSH dial error")
	}
}

func TestExecuteMikrotikBackupSuccess(t *testing.T) {
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		ch.Write([]byte("# RouterOS config\n/ip address\nadd address=10.0.0.1/24\n"))
		ch.CloseWrite()
		// Send exit-status 0
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	fmt.Sscanf(port, "%d", &portNum)

	config, err := executeMikrotikBackup("127.0.0.1", portNum, "admin", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if config == "" {
		t.Error("expected non-empty config")
	}
}

func TestExecuteMikrotikBackupCommandError(t *testing.T) {
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		// Send exit-status 1 with no output (simulates command failure)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
		ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	fmt.Sscanf(port, "%d", &portNum)

	_, err := executeMikrotikBackup("127.0.0.1", portNum, "admin", "pass")
	if err == nil {
		t.Error("expected error from failed command")
	}
}

func TestExecuteMikrotikBackupWithOutput(t *testing.T) {
	// MikroTik SSH returns output even with non-zero exit code
	addr, cleanup := startTestSSHServer(t, func(ch ssh.Channel) {
		ch.Write([]byte("# partial config\n"))
		ch.CloseWrite()
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
		ch.Close()
	})
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	var portNum uint16
	fmt.Sscanf(port, "%d", &portNum)

	config, err := executeMikrotikBackup("127.0.0.1", portNum, "admin", "pass")
	if err != nil {
		t.Fatalf("expected success when output present despite exit code, got: %v", err)
	}
	if config == "" {
		t.Error("expected non-empty config")
	}
}

func TestExecuteMikrotikBackupSessionError(t *testing.T) {
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
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)

		// Reject all channel requests to trigger NewSession error
		for newChannel := range chans {
			newChannel.Reject(ssh.Prohibited, "no sessions allowed")
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint16
	fmt.Sscanf(port, "%d", &portNum)

	_, err = executeMikrotikBackup("127.0.0.1", portNum, "admin", "pass")
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
		defer conn.Close()

		sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			ch, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range requests {
					if req.Type == "exec" {
						req.Reply(true, nil)
						handler(ch)
						return
					}
					req.Reply(false, nil)
				}
			}()
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
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
