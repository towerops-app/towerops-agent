package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

func TestChannelMsgSerialization(t *testing.T) {
	msg := channelMsg{
		Topic:   "agent:123",
		Event:   "phx_join",
		Payload: json.RawMessage(`{"token":"test"}`),
		Ref:     strPtr("1"),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	checks := []string{"agent:123", "phx_join", "token", "test"}
	for _, c := range checks {
		if !contains(s, c) {
			t.Errorf("expected %q in JSON output %q", c, s)
		}
	}
}

func TestChannelMsgDeserialization(t *testing.T) {
	raw := `{"topic":"agent:123","event":"phx_reply","payload":{"status":"ok"},"ref":"1"}`
	var msg channelMsg
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Topic != "agent:123" {
		t.Errorf("topic: got %q, want %q", msg.Topic, "agent:123")
	}
	if msg.Event != "phx_reply" {
		t.Errorf("event: got %q, want %q", msg.Event, "phx_reply")
	}
	if msg.Ref == nil || *msg.Ref != "1" {
		t.Errorf("ref: got %v, want %q", msg.Ref, "1")
	}
}

func TestChannelMsgNullRef(t *testing.T) {
	raw := `{"topic":"agent:123","event":"job","payload":{},"ref":null}`
	var msg channelMsg
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Ref != nil {
		t.Errorf("expected nil ref, got %q", *msg.Ref)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func testPools(t *testing.T) *jobPools {
	t.Helper()
	p := &jobPools{
		snmp:     newWorkerPool(4),
		mikrotik: newWorkerPool(4),
		ping:     newWorkerPool(4),
	}
	t.Cleanup(func() { p.snmp.stop(); p.mikrotik.stop(); p.ping.stop() })
	return p
}

// makeJobPayload creates a base64-encoded protobuf job list payload.
func makeJobPayload(jobs ...*pb.AgentJob) json.RawMessage {
	list := &pb.AgentJobList{Jobs: jobs}
	bin, _ := proto.Marshal(list)
	payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})
	return payload
}

func TestHandleMessage(t *testing.T) {
	t.Run("phx_reply", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		handleMessage(context.Background(), channelMsg{Event: "phx_reply", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh)
		// Just verify it doesn't panic
	})

	t.Run("jobs valid protobuf", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()

		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:      "j1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		})

		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
		// Wait for goroutine to finish
		select {
		case <-snmpCh:
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for snmp result")
		}
	})

	t.Run("invalid payload json", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: json.RawMessage(`not json`)}, testPools(t), snmpCh, mtCh, credCh, monCh)
		// Should log error but not panic
	})

	t.Run("invalid base64", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
	})

	t.Run("restart", func(t *testing.T) {
		origExit := osExit
		defer func() { osExit = origExit }()

		var exitCode int
		osExit = func(code int) { exitCode = code }

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		handleMessage(context.Background(), channelMsg{Event: "restart", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh)

		if exitCode != 0 {
			t.Errorf("expected exit code 0, got %d", exitCode)
		}
	})

	t.Run("update success", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		var calledURL string
		doSelfUpdate = func(url, checksum string) error {
			calledURL = url
			return nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)

		if calledURL != "https://example.com/agent" {
			t.Errorf("expected update URL %q, got %q", "https://example.com/agent", calledURL)
		}
	})

	t.Run("update invalid payload", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		called := false
		doSelfUpdate = func(url, checksum string) error {
			called = true
			return nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		// Missing URL field
		payload, _ := json.Marshal(map[string]string{"checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)

		if called {
			t.Error("selfUpdate should not be called with empty URL")
		}
	})

	t.Run("update error", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		doSelfUpdate = func(url, checksum string) error {
			return fmt.Errorf("download failed")
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
		// Should log error but not panic
	})

	t.Run("update missing checksum", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		called := false
		doSelfUpdate = func(url, checksum string) error {
			called = true
			return nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)

		if called {
			t.Error("selfUpdate should not be called with empty checksum")
		}
	})

	t.Run("unknown event", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		handleMessage(context.Background(), channelMsg{Event: "some_unknown_event", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh)
		// Should just log and not panic
	})

	t.Run("discovery_job event", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()

		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:      "d1",
			JobType:    pb.JobType_DISCOVER,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		})
		handleMessage(context.Background(), channelMsg{Event: "discovery_job", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
		select {
		case <-snmpCh:
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for discovery result")
		}
	})

	t.Run("backup_job event", func(t *testing.T) {
		origDial := mikrotikDial
		origSSH := sshBackup
		defer func() { mikrotikDial = origDial; sshBackup = origSSH }()

		sshBackup = func(ip string, port uint16, username, password string) (string, error) {
			return "/ip address\nadd address=10.0.0.1/24", nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:          "backup:dev1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
		})
		handleMessage(context.Background(), channelMsg{Event: "backup_job", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh)
		select {
		case result := <-mtCh:
			if result.Error != "" {
				t.Errorf("unexpected error: %s", result.Error)
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for backup result")
		}
	})
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, v)
		}
	}

	// Nil/empty should not panic
	zeroBytes(nil)
	zeroBytes([]byte{})
}

func TestNextBackoff(t *testing.T) {
	maxDelay := 60 * time.Second

	// Test doubling with jitter
	for i := 0; i < 100; i++ {
		current := 2 * time.Second
		next := nextBackoff(current, maxDelay)
		doubled := current * 2
		maxWithJitter := doubled + doubled/4
		if next < doubled || next > maxWithJitter {
			t.Errorf("nextBackoff(%v) = %v, want in [%v, %v]", current, next, doubled, maxWithJitter)
		}
	}

	// Test cap at max
	for i := 0; i < 100; i++ {
		next := nextBackoff(30*time.Second, maxDelay)
		if next > maxDelay+maxDelay/4 {
			t.Errorf("nextBackoff(30s) = %v, exceeded max+jitter", next)
		}
	}

	// Test that already-at-max stays at max (with jitter)
	for i := 0; i < 100; i++ {
		next := nextBackoff(maxDelay, maxDelay)
		maxWithJitter := maxDelay + maxDelay/4
		if next < maxDelay || next > maxWithJitter {
			t.Errorf("nextBackoff(max) = %v, want in [%v, %v]", next, maxDelay, maxWithJitter)
		}
	}
}

func TestDispatchJob(t *testing.T) {
	t.Run("MIKROTIK", func(t *testing.T) {
		origDial := mikrotikDial
		defer func() { mikrotikDial = origDial }()
		mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
			return nil, fmt.Errorf("not reachable")
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:          "mt1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}, testPools(t), snmpCh, mtCh, credCh, monCh)

		select {
		case result := <-mtCh:
			if result.Error == "" {
				t.Error("expected error from unreachable device")
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out")
		}
	})

	t.Run("TEST_CREDENTIALS", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("refused")
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "tc1",
			JobType:    pb.JobType_TEST_CREDENTIALS,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh)

		select {
		case result := <-credCh:
			if result.Success {
				t.Error("expected failure")
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out")
		}
	})

	t.Run("PING", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(ip string, timeoutMs int) (float64, error) {
			return 5.5, nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "p1",
			JobType:    pb.JobType_PING,
			SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh)

		select {
		case result := <-monCh:
			if result.Status != "success" {
				t.Errorf("expected success, got %q", result.Status)
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out")
		}
	})

	t.Run("default SNMP", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "s1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh)

		select {
		case <-snmpCh:
		case <-time.After(2 * time.Second):
			t.Error("timed out")
		}
	})
}
