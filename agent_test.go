package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
		checks:   newWorkerPool(4),
	}
	t.Cleanup(func() { p.snmp.stop(); p.mikrotik.stop(); p.ping.stop(); p.checks.stop() })
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
		checkCh := make(chan *pb.CheckResult, 1)
		handleMessage(context.Background(), channelMsg{Event: "phx_reply", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		checkCh := make(chan *pb.CheckResult, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:      "j1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		})

		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		checkCh := make(chan *pb.CheckResult, 1)
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: json.RawMessage(`not json`)}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("invalid base64", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
	})

	t.Run("restart", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		shouldEnd := handleMessage(context.Background(), channelMsg{Event: "restart", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		if !shouldEnd {
			t.Error("expected handleMessage to return true for restart")
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
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		checkCh := make(chan *pb.CheckResult, 1)
		// Missing URL field
		payload, _ := json.Marshal(map[string]string{"checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent"})
		handleMessage(context.Background(), channelMsg{Event: "update", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		if called {
			t.Error("selfUpdate should not be called with empty checksum")
		}
	})

	t.Run("unknown event", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		handleMessage(context.Background(), channelMsg{Event: "some_unknown_event", Payload: json.RawMessage(`{}`)}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should just log and not panic
	})

	t.Run("check_jobs valid", func(t *testing.T) {
		checkList := &pb.CheckList{Checks: []*pb.Check{
			{Id: "c1", CheckType: "tcp", TimeoutMs: 1000,
				Config: &pb.Check_Tcp{Tcp: &pb.TcpCheckConfig{Host: "127.0.0.1", Port: 1}}},
		}}
		bin, _ := proto.Marshal(checkList)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		handleMessage(context.Background(), channelMsg{Event: "check_jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		select {
		case <-checkCh:
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for check result")
		}
	})

	t.Run("check_jobs invalid json", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		handleMessage(context.Background(), channelMsg{Event: "check_jobs", Payload: json.RawMessage(`not json`)}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("check_jobs invalid base64", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		handleMessage(context.Background(), channelMsg{Event: "check_jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("check_jobs invalid protobuf", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		handleMessage(context.Background(), channelMsg{Event: "check_jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
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
		checkCh := make(chan *pb.CheckResult, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:      "d1",
			JobType:    pb.JobType_DISCOVER,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		})
		handleMessage(context.Background(), channelMsg{Event: "discovery_job", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		checkCh := make(chan *pb.CheckResult, 1)

		payload := makeJobPayload(&pb.AgentJob{
			JobId:          "backup:dev1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
		})
		handleMessage(context.Background(), channelMsg{Event: "backup_job", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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

func TestHandleMessageRejectsOversizedPayload(t *testing.T) {
	snmpCh := make(chan *pb.SnmpResult, 1)
	mtCh := make(chan *pb.MikrotikResult, 1)
	credCh := make(chan *pb.CredentialTestResult, 1)
	monCh := make(chan *pb.MonitoringCheck, 1)
	checkCh := make(chan *pb.CheckResult, 1)

	// Create a binary payload larger than maxJobPayloadBytes
	oversized := make([]byte, maxJobPayloadBytes+1)
	encoded := base64.StdEncoding.EncodeToString(oversized)
	payload, _ := json.Marshal(map[string]string{"binary": encoded})

	handleMessage(context.Background(), channelMsg{Event: "jobs", Payload: payload}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

	// Verify no jobs were dispatched
	select {
	case <-snmpCh:
		t.Error("expected no SNMP result for oversized payload")
	case <-time.After(100 * time.Millisecond):
		// Good — nothing dispatched
	}
}

func TestBufferPoolZeroesOnReturn(t *testing.T) {
	pool := &sync.Pool{
		New: func() any {
			b := make([]byte, 0, 64)
			return &b
		},
	}

	// Get a buffer, write some data, return it
	bp := pool.Get().(*[]byte)
	*bp = append((*bp)[:0], []byte("sensitive credentials data here")...)
	full := (*bp)[:cap(*bp)]

	// Simulate the zeroing that sendBinaryResult should do
	zeroBytes(full)
	*bp = full[:0]
	pool.Put(bp)

	// Get the buffer back and verify it's zeroed
	bp2 := pool.Get().(*[]byte)
	full2 := (*bp2)[:cap(*bp2)]
	for i, b := range full2 {
		if b != 0 {
			t.Errorf("byte[%d] = %d, expected 0 — pool buffer not zeroed", i, b)
			break
		}
	}
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
		checkCh := make(chan *pb.CheckResult, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:          "mt1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		checkCh := make(chan *pb.CheckResult, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "tc1",
			JobType:    pb.JobType_TEST_CREDENTIALS,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		checkCh := make(chan *pb.CheckResult, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "p1",
			JobType:    pb.JobType_PING,
			SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		checkCh := make(chan *pb.CheckResult, 1)

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "s1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		select {
		case <-snmpCh:
		case <-time.After(2 * time.Second):
			t.Error("timed out")
		}
	})
}

func TestRunSessionRejectsFailedJoin(t *testing.T) {
	origTimeout := joinTimeout
	defer func() { joinTimeout = origTimeout }()
	joinTimeout = 2 * time.Second

	// Start a fake WebSocket server that accepts the upgrade then sends a phx_error join reply
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

		// Read HTTP upgrade request
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		reqStr := string(buf[:n])

		// Extract key and compute accept
		key := extractWSKey(reqStr)
		accept := computeAcceptKey(key)

		// Send valid 101 upgrade
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Read the join message (masked WebSocket frame) — just consume it
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)

		// Send phx_error reply as an unmasked text frame
		reply, _ := json.Marshal(channelMsg{
			Topic:   "agent:agent-0",
			Event:   "phx_reply",
			Payload: json.RawMessage(`{"status":"error","response":{"reason":"invalid token"}}`),
			Ref:     strPtr("1"),
		})
		frame := makeTextFrame(reply)
		_, _ = conn.Write(frame)

		// Keep connection open for a bit
		time.Sleep(time.Second)
	}()

	addr := ln.Addr().String()
	err = runSession(context.Background(), "ws://"+addr, "bad-token")
	if err == nil {
		t.Fatal("expected error from rejected join")
	}
	if !strings.Contains(err.Error(), "join rejected") {
		t.Errorf("expected 'join rejected' in error, got: %v", err)
	}
}

func TestRunSessionJoinTimeout(t *testing.T) {
	origTimeout := joinTimeout
	defer func() { joinTimeout = origTimeout }()
	joinTimeout = 500 * time.Millisecond

	// Server that upgrades but never sends a join reply
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
		reqStr := string(buf[:n])
		key := extractWSKey(reqStr)
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Read join frame but never reply
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)

		time.Sleep(5 * time.Second)
	}()

	addr := ln.Addr().String()
	start := time.Now()
	err = runSession(context.Background(), "ws://"+addr, "token")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "join timeout") {
		t.Errorf("expected 'join timeout' in error, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("took too long (%v), timeout didn't trigger", elapsed)
	}
}

// extractWSKey extracts the Sec-WebSocket-Key from a raw HTTP request.
func extractWSKey(req string) string {
	for _, line := range strings.Split(req, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sec-websocket-key: ") {
			return strings.TrimSpace(line[len("Sec-WebSocket-Key: "):])
		}
	}
	return ""
}

// makeTextFrame creates an unmasked WebSocket text frame (server→client).
func makeTextFrame(payload []byte) []byte {
	length := len(payload)
	var frame []byte
	frame = append(frame, 0x81) // FIN + text
	if length <= 125 {
		frame = append(frame, byte(length))
	} else if length <= 65535 {
		frame = append(frame, 126, byte(length>>8), byte(length))
	}
	frame = append(frame, payload...)
	return frame
}

func TestDispatchJobCancelledContext(t *testing.T) {
	// Use pools with size 1 (1 worker + 4 queue slots) and fill them
	// so that submit reliably fails with cancelled context.
	p := &jobPools{
		snmp:     newWorkerPool(1),
		mikrotik: newWorkerPool(1),
		ping:     newWorkerPool(1),
		checks:   newWorkerPool(1),
	}
	t.Cleanup(func() { p.snmp.stop(); p.mikrotik.stop(); p.ping.stop(); p.checks.stop() })

	done := make(chan struct{})

	// Block each pool's worker + fill queue slots
	fillPool := func(pool *workerPool) {
		started := make(chan struct{})
		pool.submit(context.Background(), func() { close(started); <-done })
		<-started
		for range 4 {
			pool.submit(context.Background(), func() { <-done })
		}
	}
	fillPool(p.snmp)
	fillPool(p.mikrotik)
	fillPool(p.ping)

	snmpCh := make(chan *pb.SnmpResult, 1)
	mtCh := make(chan *pb.MikrotikResult, 1)
	credCh := make(chan *pb.CredentialTestResult, 1)
	monCh := make(chan *pb.MonitoringCheck, 1)
	checkCh := make(chan *pb.CheckResult, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All dispatch types should hit the "pool full" warning
	dispatchJob(ctx, &pb.AgentJob{
		JobId: "s1", JobType: pb.JobType_POLL, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "m1", JobType: pb.JobType_MIKROTIK, MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1"},
	}, p, snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "tc1", JobType: pb.JobType_TEST_CREDENTIALS, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "p1", JobType: pb.JobType_PING, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

	close(done)
}

// fakeWSServer is a test helper that sets up a WebSocket server for runSession tests.
type fakeWSServer struct {
	ln   net.Listener
	conn net.Conn
}

func newFakeWSServer(t *testing.T) *fakeWSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &fakeWSServer{ln: ln}
}

func (s *fakeWSServer) addr() string { return s.ln.Addr().String() }

// acceptAndJoin accepts one WS connection and responds with a successful join.
func (s *fakeWSServer) acceptAndJoin(t *testing.T) {
	t.Helper()
	conn, err := s.ln.Accept()
	if err != nil {
		t.Logf("accept: %v", err)
		return
	}
	s.conn = conn

	// Read HTTP upgrade
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	key := extractWSKey(string(buf[:n]))
	accept := computeAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	_, _ = conn.Write([]byte(resp))

	// Read join frame
	frameBuf := make([]byte, 4096)
	_, _ = conn.Read(frameBuf)

	// Send join OK
	reply, _ := json.Marshal(channelMsg{
		Topic:   "agent:agent-0",
		Event:   "phx_reply",
		Payload: json.RawMessage(`{"status":"ok"}`),
		Ref:     strPtr("1"),
	})
	_, _ = conn.Write(makeTextFrame(reply))
}

// sendEvent sends a channel message to the connected client.
func (s *fakeWSServer) sendEvent(event string, payload json.RawMessage) {
	msg, _ := json.Marshal(channelMsg{
		Topic:   "agent:agent-0",
		Event:   event,
		Payload: payload,
	})
	_, _ = s.conn.Write(makeTextFrame(msg))
}

// close shuts down the server connection.
func (s *fakeWSServer) close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func TestRunSessionCtxCancel(t *testing.T) {
	srv := newFakeWSServer(t)

	go srv.acceptAndJoin(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- runSession(ctx, "ws://"+srv.addr(), "token")
	}()

	// Give the session time to enter the main loop
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on ctx cancel, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("runSession did not exit after ctx cancel")
	}
	srv.close()
}

func TestRunSessionReadError(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		// Small delay, then close to trigger read error
		time.Sleep(200 * time.Millisecond)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	if err == nil {
		t.Error("expected read error")
	}
	if !strings.Contains(err.Error(), "read:") {
		t.Errorf("expected 'read:' in error, got: %v", err)
	}
}

func TestRunSessionInvalidMessage(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		// Send invalid JSON — should be logged but not crash
		time.Sleep(100 * time.Millisecond)
		_, _ = srv.conn.Write(makeTextFrame([]byte("not json")))
		// Then close to end session
		time.Sleep(100 * time.Millisecond)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	// Should end with read error from close, not crash
	if err == nil {
		t.Error("expected error")
	}
}

func TestRunSessionConnectError(t *testing.T) {
	err := runSession(context.Background(), "ws://127.0.0.1:1", "token")
	if err == nil {
		t.Error("expected connect error")
	}
	if !strings.Contains(err.Error(), "connect:") {
		t.Errorf("expected 'connect:' in error, got: %v", err)
	}
}

func TestRunSessionJoinWriteError(t *testing.T) {
	// Server accepts WS upgrade but closes immediately after
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
		// Read HTTP upgrade
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		key := extractWSKey(string(buf[:n]))
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		// Close immediately so join write may fail
		_ = conn.Close()
	}()

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token")
	if err == nil {
		t.Error("expected error")
	}
}

func TestRunSessionJoinUnmarshalError(t *testing.T) {
	// Server sends binary garbage as join reply
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
		key := extractWSKey(string(buf[:n]))
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)
		// Send invalid JSON as reply
		_, _ = conn.Write(makeTextFrame([]byte("{invalid json")))
		time.Sleep(time.Second)
	}()

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token")
	if err == nil {
		t.Error("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "join reply unmarshal") {
		t.Errorf("expected 'join reply unmarshal' in error, got: %v", err)
	}
}

func TestRunSessionReadErrorDuringJoin(t *testing.T) {
	// Server sends upgrade then closes before sending join reply
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
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		key := extractWSKey(string(buf[:n]))
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)
		// Close without sending reply
		_ = conn.Close()
	}()

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token")
	if err == nil {
		t.Error("expected read during join error")
	}
	if !strings.Contains(err.Error(), "read during join") {
		t.Errorf("expected 'read during join' in error, got: %v", err)
	}
}

func TestRunAgentReconnectOnError(t *testing.T) {
	// Server that fails first connection then succeeds, then sends restart
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	connCount := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connCount++
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			key := extractWSKey(string(buf[:n]))
			accept := computeAcceptKey(key)

			if connCount == 1 {
				// First connection: upgrade then close immediately
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
				_, _ = conn.Write([]byte(resp))
				frameBuf := make([]byte, 4096)
				_, _ = conn.Read(frameBuf)
				_ = conn.Close()
			} else {
				// Second connection: proper session with restart
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
				_, _ = conn.Write([]byte(resp))
				frameBuf := make([]byte, 4096)
				_, _ = conn.Read(frameBuf)
				reply, _ := json.Marshal(channelMsg{
					Topic:   "agent:agent-0",
					Event:   "phx_reply",
					Payload: json.RawMessage(`{"status":"ok"}`),
					Ref:     strPtr("1"),
				})
				_, _ = conn.Write(makeTextFrame(reply))
				time.Sleep(50 * time.Millisecond)
				restart, _ := json.Marshal(channelMsg{
					Topic:   "agent:agent-0",
					Event:   "restart",
					Payload: json.RawMessage(`{}`),
				})
				_, _ = conn.Write(makeTextFrame(restart))
				time.Sleep(time.Second)
				_ = conn.Close()
			}
		}
	}()

	origExit := osExit
	defer func() { osExit = origExit }()
	exitCalled := make(chan int, 1)
	osExit = func(code int) { exitCalled <- code }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://"+ln.Addr().String(), "token")
		close(done)
	}()

	select {
	case code := <-exitCalled:
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Error("runAgent did not reconnect and restart")
	}
}

func TestRunAgentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://127.0.0.1:1", "token")
		close(done)
	}()

	select {
	case <-done:
		// runAgent returned as expected
	case <-time.After(5 * time.Second):
		t.Error("runAgent did not return after context cancellation")
	}
}

func TestRunAgentRestart(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	exitCalled := make(chan int, 1)
	osExit = func(code int) {
		exitCalled <- code
	}

	// Start a fake WebSocket server that accepts the join and sends restart
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
		reqStr := string(buf[:n])
		key := extractWSKey(reqStr)
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Read join frame
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)

		// Send join OK reply
		reply, _ := json.Marshal(channelMsg{
			Topic:   "agent:agent-0",
			Event:   "phx_reply",
			Payload: json.RawMessage(`{"status":"ok"}`),
			Ref:     strPtr("1"),
		})
		_, _ = conn.Write(makeTextFrame(reply))

		// Small delay then send restart event
		time.Sleep(50 * time.Millisecond)
		restart, _ := json.Marshal(channelMsg{
			Topic:   "agent:agent-0",
			Event:   "restart",
			Payload: json.RawMessage(`{}`),
		})
		_, _ = conn.Write(makeTextFrame(restart))

		// Keep connection open briefly
		time.Sleep(2 * time.Second)
	}()

	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://"+addr, "test-token")
		close(done)
	}()

	select {
	case code := <-exitCalled:
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("osExit was not called after restart")
	}
}

// readMaskedFrame reads a single masked WebSocket frame from the server side.
func readMaskedFrame(conn net.Conn) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(conn, maskKey[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, nil
}

// drainFrames reads and discards client frames until stop channel is closed or error.
func drainFrames(conn net.Conn, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := readMaskedFrame(conn); err != nil {
			select {
			case <-stop:
				return
			default:
				continue // timeout, retry
			}
		}
	}
}

func TestRunSessionProcessesJobResults(t *testing.T) {
	// Mock external dependencies for fast execution
	origSnmpDial := snmpDial
	origMtDial := mikrotikDial
	origPing := doPing
	defer func() {
		snmpDial = origSnmpDial
		mikrotikDial = origMtDial
		doPing = origPing
	}()

	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}
	mikrotikDial = func(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
		return nil, fmt.Errorf("unreachable")
	}
	doPing = func(ip string, timeoutMs int) (float64, error) {
		return 1.5, nil
	}

	srv := newFakeWSServer(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		srv.acceptAndJoin(t)

		// Drain client frames so writes don't block
		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)

		time.Sleep(100 * time.Millisecond)

		// SNMP job → snmpResultCh → snmpBatch → flushSnmpBatch → sendBinaryResult
		srv.sendEvent("jobs", makeJobPayload(&pb.AgentJob{
			JobId: "s1", JobType: pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}))

		// Mikrotik job → mikrotikResultCh → sendBinaryResult("mikrotik_result")
		srv.sendEvent("jobs", makeJobPayload(&pb.AgentJob{
			JobId: "m1", JobType: pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}))

		// Ping job → monitoringCheckCh → sendBinaryResult("monitoring_check")
		srv.sendEvent("jobs", makeJobPayload(&pb.AgentJob{
			JobId: "p1", JobType: pb.JobType_PING, DeviceId: "dev1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}))

		// Credential test → credTestResultCh → sendBinaryResult("credential_test_result")
		srv.sendEvent("jobs", makeJobPayload(&pb.AgentJob{
			JobId: "ct1", JobType: pb.JobType_TEST_CREDENTIALS,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}))

		// Check job → checkResultCh → sendBinaryResult("check_result")
		checkList := &pb.CheckList{Checks: []*pb.Check{
			{Id: "c1", CheckType: "tcp", TimeoutMs: 500,
				Config: &pb.Check_Tcp{Tcp: &pb.TcpCheckConfig{Host: "127.0.0.1", Port: 1}}},
		}}
		bin, _ := proto.Marshal(checkList)
		checkPayload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})
		srv.sendEvent("check_jobs", checkPayload)

		// Wait for results to flow through all channels
		time.Sleep(2 * time.Second)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	<-serverDone
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestRunSessionSnmpBatchThreshold(t *testing.T) {
	origSnmpDial := snmpDial
	defer func() { snmpDial = origSnmpDial }()

	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}

	srv := newFakeWSServer(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		srv.acceptAndJoin(t)

		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)

		time.Sleep(100 * time.Millisecond)

		// Send 55 SNMP jobs to trigger batch threshold (>=50)
		jobs := make([]*pb.AgentJob, 55)
		for i := range jobs {
			jobs[i] = &pb.AgentJob{
				JobId:      fmt.Sprintf("s%d", i),
				JobType:    pb.JobType_POLL,
				SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
			}
		}
		srv.sendEvent("jobs", makeJobPayload(jobs...))

		time.Sleep(3 * time.Second)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	<-serverDone
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestExecuteCheckPoolFull(t *testing.T) {
	// newWorkerPool(1) creates 1 worker goroutine + queue buffer of 1*4=4
	// We need to block the worker AND fill all 4 queue slots to make submit block.
	p := &jobPools{
		snmp:     newWorkerPool(4),
		mikrotik: newWorkerPool(4),
		ping:     newWorkerPool(4),
		checks:   newWorkerPool(1),
	}
	t.Cleanup(func() { p.snmp.stop(); p.mikrotik.stop(); p.ping.stop(); p.checks.stop() })

	done := make(chan struct{})
	started := make(chan struct{})

	// Block the single worker
	p.checks.submit(context.Background(), func() {
		close(started)
		<-done
	})
	<-started

	// Fill all 4 queue slots
	for range 4 {
		p.checks.submit(context.Background(), func() { <-done })
	}

	// Pool is now truly full — submit with cancelled ctx will reliably fail
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checkCh := make(chan *pb.CheckResult, 1)
	check := &pb.Check{Id: "c1", CheckType: "tcp", TimeoutMs: 1000}
	executeCheck(ctx, check, p, checkCh)
	// Should log "check rejected (pool full)" but not panic
	close(done)
}

func TestExecuteCheckCtxDoneInClosure(t *testing.T) {
	// Tests the ctx.Done path inside executeCheck's closure:
	// Submit succeeds, check runs, but result channel is blocked so ctx.Done fires.
	p := testPools(t)
	ctx, cancel := context.WithCancel(context.Background())
	checkCh := make(chan *pb.CheckResult) // unbuffered, no reader

	check := &pb.Check{Id: "c1", CheckType: "tcp", TimeoutMs: 100,
		Config: &pb.Check_Tcp{Tcp: &pb.TcpCheckConfig{Host: "127.0.0.1", Port: 1}}}

	executeCheck(ctx, check, p, checkCh)

	// Wait for the check to complete (TCP to port 1 fails fast)
	time.Sleep(500 * time.Millisecond)
	// Cancel ctx so the closure's select picks ctx.Done instead of blocked channel send
	cancel()
	time.Sleep(100 * time.Millisecond)
}

func TestRunSessionRestartInMainLoop(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)

		time.Sleep(100 * time.Millisecond)
		// Send restart event — exercised in the main loop select
		srv.sendEvent("restart", json.RawMessage(`{}`))
		time.Sleep(time.Second)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	if err != errRestartRequested {
		t.Errorf("expected errRestartRequested, got: %v", err)
	}
}

func TestRunSessionHeartbeats(t *testing.T) {
	// Use short heartbeat intervals to exercise heartbeat paths
	origHB := heartbeatInterval
	origCHB := channelHeartbeatInterval
	defer func() {
		heartbeatInterval = origHB
		channelHeartbeatInterval = origCHB
	}()
	heartbeatInterval = 100 * time.Millisecond
	channelHeartbeatInterval = 100 * time.Millisecond

	srv := newFakeWSServer(t)
	go func() {
		srv.acceptAndJoin(t)
		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)
		// Let heartbeats fire a few times
		time.Sleep(500 * time.Millisecond)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestRunAgentCancelDuringRetry(t *testing.T) {
	// Connects to a port nothing listens on, then cancel during retry delay
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://127.0.0.1:1", "token")
		close(done)
	}()

	// Wait for first connection attempt to fail and retry delay to start
	time.Sleep(1500 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// runAgent returned after cancel during retry
	case <-time.After(5 * time.Second):
		t.Error("runAgent did not return after cancel during retry")
	}
}

func TestRunSessionWriteError(t *testing.T) {
	// Server accepts join, drains one frame, then sends a jobs event.
	// Meanwhile we close the connection from the server side to trigger
	// a write error in the writer goroutine when it tries to send results.
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)

		// Send a bulk of events so the client tries to write back
		time.Sleep(100 * time.Millisecond)

		// Close the connection from the server side — any writes by the
		// client's writer goroutine will fail, triggering writeErrCh.
		srv.close()
	}()

	// Use short heartbeat to generate write traffic
	origCHB := channelHeartbeatInterval
	defer func() { channelHeartbeatInterval = origCHB }()
	channelHeartbeatInterval = 50 * time.Millisecond

	err := runSession(context.Background(), "ws://"+srv.addr(), "token")
	if err == nil {
		t.Error("expected error from write or read failure")
	}
	// Either "read:" or "write:" error is acceptable
}
