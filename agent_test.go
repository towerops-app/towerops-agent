// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"
)

const testWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func computeAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + testWebSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

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
		if !strings.Contains(s, c) {
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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "phx_reply", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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

		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Wait for goroutine to finish
		select {
		case <-snmpCh:
		case <-time.After(500 * time.Millisecond):
			t.Error("timed out waiting for snmp result")
		}
	})

	t.Run("invalid payload json", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: json.RawMessage(`not json`)}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("invalid base64", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
	})

	t.Run("restart", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		shouldEnd, reason := handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "restart", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		if !shouldEnd {
			t.Error("expected handleMessage to return true for restart")
		}
		if reason != errRestartRequested {
			t.Fatalf("expected restart reason %v, got %v", errRestartRequested, reason)
		}
	})

	t.Run("phoenix channel teardown reconnects", func(t *testing.T) {
		events := []string{"phx_error", "phx_close"}

		for _, event := range events {
			snmpCh := make(chan *pb.SnmpResult, 1)
			mtCh := make(chan *pb.MikrotikResult, 1)
			credCh := make(chan *pb.CredentialTestResult, 1)
			monCh := make(chan *pb.MonitoringCheck, 1)
			checkCh := make(chan *pb.CheckResult, 1)

			shouldEnd, reason := handleMessage(
				context.Background(),
				channelMsg{Topic: "agent:test", Event: event, Payload: json.RawMessage(`{}`)},
				"agent:test",
				testPools(t),
				snmpCh,
				mtCh,
				credCh,
				monCh,
				checkCh,
				make(chan *pb.LldpTopologyResult, 1),
			)

			if !shouldEnd {
				t.Fatalf("expected handleMessage to end session for %s", event)
			}
			if reason != errChannelReloaded {
				t.Fatalf("expected reload reason %v for %s, got %v", errChannelReloaded, event, reason)
			}
		}
	})

	t.Run("update success", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		var calledURL string
		doSelfUpdate = func(_ context.Context, url, checksum string) error {
			calledURL = url
			return nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		if calledURL != "https://example.com/agent" {
			t.Errorf("expected update URL %q, got %q", "https://example.com/agent", calledURL)
		}
	})

	t.Run("update invalid payload", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		called := false
		doSelfUpdate = func(_ context.Context, url, checksum string) error {
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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

		if called {
			t.Error("selfUpdate should not be called with empty URL")
		}
	})

	t.Run("update error", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		doSelfUpdate = func(_ context.Context, url, checksum string) error {
			return fmt.Errorf("download failed")
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("update missing checksum", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		called := false
		doSelfUpdate = func(_ context.Context, url, checksum string) error {
			called = true
			return nil
		}

		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "some_unknown_event", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		select {
		case <-checkCh:
		case <-time.After(time.Second):
			t.Error("timed out waiting for check result")
		}
	})

	t.Run("check_jobs invalid json", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: json.RawMessage(`not json`)}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("check_jobs invalid base64", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		// Should log error but not panic
	})

	t.Run("check_jobs invalid protobuf", func(t *testing.T) {
		snmpCh := make(chan *pb.SnmpResult, 1)
		mtCh := make(chan *pb.MikrotikResult, 1)
		credCh := make(chan *pb.CredentialTestResult, 1)
		monCh := make(chan *pb.MonitoringCheck, 1)
		checkCh := make(chan *pb.CheckResult, 1)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "discovery_job", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		select {
		case <-snmpCh:
		case <-time.After(500 * time.Millisecond):
			t.Error("timed out waiting for discovery result")
		}
	})

	t.Run("backup_job event", func(t *testing.T) {
		origDial := mikrotikDial
		origSSH := sshBackup
		defer func() { mikrotikDial = origDial; sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
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
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "backup_job", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))
		select {
		case result := <-mtCh:
			if result.Error != "" {
				t.Errorf("unexpected error: %s", result.Error)
			}
		case <-time.After(500 * time.Millisecond):
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

	_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), snmpCh, mtCh, credCh, monCh, checkCh, make(chan *pb.LldpTopologyResult, 1))

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
		mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
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
		case <-time.After(500 * time.Millisecond):
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
		case <-time.After(500 * time.Millisecond):
			t.Error("timed out")
		}
	})

	t.Run("PING", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
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
		case <-time.After(500 * time.Millisecond):
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
		case <-time.After(500 * time.Millisecond):
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
		time.Sleep(200 * time.Millisecond)
	}()

	addr := ln.Addr().String()
	err = runSession(context.Background(), "ws://"+addr, "bad-token", nil)
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

		time.Sleep(2 * time.Second)
	}()

	addr := ln.Addr().String()
	start := time.Now()
	err = runSession(context.Background(), "ws://"+addr, "token", nil)
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
	ln    net.Listener
	conn  net.Conn
	topic string
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

	// Read join frame and extract topic
	joinPayload, err := readMaskedFrame(conn)
	if err == nil {
		var joinMsg channelMsg
		if err := json.Unmarshal(joinPayload, &joinMsg); err == nil && joinMsg.Topic != "" {
			s.topic = joinMsg.Topic
		}
	}
	if s.topic == "" {
		s.topic = "agent:agent-0"
	}

	// Send join OK
	reply, _ := json.Marshal(channelMsg{
		Topic:   s.topic,
		Event:   "phx_reply",
		Payload: json.RawMessage(`{"status":"ok"}`),
		Ref:     strPtr("1"),
	})
	_, _ = conn.Write(makeTextFrame(reply))
}

// sendEvent sends a channel message to the connected client.
func (s *fakeWSServer) sendEvent(event string, payload json.RawMessage) {
	msg, _ := json.Marshal(channelMsg{
		Topic:   s.topic,
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
		done <- runSession(ctx, "ws://"+srv.addr(), "token", nil)
	}()

	// Give the session time to enter the main loop
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on ctx cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runSession did not exit after ctx cancel")
	}
	srv.close()
}

func TestRunSessionRestartDoesNotWaitForServerClose(t *testing.T) {
	srv := newFakeWSServer(t)
	defer srv.close()

	go func() {
		srv.acceptAndJoin(t)
		srv.sendEvent("restart", json.RawMessage(`{}`))
	}()

	done := make(chan error, 1)
	go func() {
		done <- runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errRestartRequested) {
			t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runSession waited for the server to close after restart")
	}
}

func TestRunSessionReadError(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		// Small delay, then close to trigger read error
		time.Sleep(200 * time.Millisecond)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
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

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	// Should end with read error from close, not crash
	if err == nil {
		t.Error("expected error")
	}
}

func TestRunSessionConnectError(t *testing.T) {
	err := runSession(context.Background(), "ws://127.0.0.1:1", "token", nil)
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

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token", nil)
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

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token", nil)
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

	err = runSession(context.Background(), "ws://"+ln.Addr().String(), "token", nil)
	if err == nil {
		t.Error("expected read during join error")
	}
	if !strings.Contains(err.Error(), "read during join") {
		t.Errorf("expected 'read during join' in error, got: %v", err)
	}
}

func TestRunAgentReconnectOnError(t *testing.T) {
	origRetry := initialRetryDelay
	defer func() { initialRetryDelay = origRetry }()
	initialRetryDelay = 50 * time.Millisecond

	// Server that fails first connection then succeeds, then sends restart.
	// Agent should reconnect (not exit) after both error and restart.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var connCount atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count := connCount.Add(1)
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			key := extractWSKey(string(buf[:n]))
			accept := computeAcceptKey(key)

			switch count {
			case 1:
				// First connection: upgrade then close immediately (triggers error reconnect)
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
				_, _ = conn.Write([]byte(resp))
				frameBuf := make([]byte, 4096)
				_, _ = conn.Read(frameBuf)
				_ = conn.Close()
			case 2:
				// Second connection: proper session with restart (triggers restart reconnect)
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
				time.Sleep(20 * time.Millisecond)
				restart, _ := json.Marshal(channelMsg{
					Topic:   "agent:agent-0",
					Event:   "restart",
					Payload: json.RawMessage(`{}`),
				})
				_, _ = conn.Write(makeTextFrame(restart))
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			default:
				// Third connection: agent successfully reconnected after restart
				_ = conn.Close()
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://"+ln.Addr().String(), "token", nil)
		close(done)
	}()

	// Wait for 3rd connection attempt (proves agent reconnected after both error and restart)
	deadline := time.After(5 * time.Second)
	for {
		if connCount.Load() >= 3 {
			cancel()
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected at least 3 connections, got %d", connCount.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	<-done
}

func TestRunAgentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://127.0.0.1:1", "token", nil)
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
	origRetry := initialRetryDelay
	defer func() { initialRetryDelay = origRetry }()
	initialRetryDelay = 50 * time.Millisecond

	// After receiving a restart event, the agent should reconnect (not exit).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var connCount atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count := connCount.Add(1)

			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			key := extractWSKey(string(buf[:n]))
			accept := computeAcceptKey(key)
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

			if count == 1 {
				// First connection: send restart event
				time.Sleep(20 * time.Millisecond)
				restart, _ := json.Marshal(channelMsg{
					Topic:   "agent:agent-0",
					Event:   "restart",
					Payload: json.RawMessage(`{}`),
				})
				_, _ = conn.Write(makeTextFrame(restart))
				time.Sleep(200 * time.Millisecond)
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://"+ln.Addr().String(), "test-token", nil)
		close(done)
	}()

	// Wait for 2nd connection (proves agent reconnected after restart instead of exiting)
	deadline := time.After(5 * time.Second)
	for {
		if connCount.Load() >= 2 {
			cancel()
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected at least 2 connections, got %d", connCount.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	<-done
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
	mikrotikDial = func(_ context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
		return nil, fmt.Errorf("unreachable")
	}
	doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
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

		// SNMP job → snmpResultCh → sendBinaryResult
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
		time.Sleep(500 * time.Millisecond)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	<-serverDone
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestRunSessionForwardsManySnmpResults(t *testing.T) {
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

		// Send enough SNMP jobs to exercise sustained result forwarding.
		jobs := make([]*pb.AgentJob, 55)
		for i := range jobs {
			jobs[i] = &pb.AgentJob{
				JobId:      fmt.Sprintf("s%d", i),
				JobType:    pb.JobType_POLL,
				SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
			}
		}
		srv.sendEvent("jobs", makeJobPayload(jobs...))

		time.Sleep(time.Second)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	<-serverDone
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestExecuteCheckPoolFull(t *testing.T) {
	// newWorkerPool(1) creates 1 worker goroutine + queue buffer of 1*4=4
	// Block the worker and fill all 4 queue slots so the next submit is rejected.
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

func TestJobPoolsStopUsesSingleTimeout(t *testing.T) {
	blocker := make(chan struct{})
	pools := &jobPools{
		snmp: newWorkerPool(1), mikrotik: newWorkerPool(1),
		ping: newWorkerPool(1), checks: newWorkerPool(1),
	}
	for _, pool := range []*workerPool{pools.snmp, pools.mikrotik, pools.ping, pools.checks} {
		started := make(chan struct{})
		pool.submit(context.Background(), func() { close(started); <-blocker })
		<-started
	}

	start := time.Now()
	timedOut := pools.stop(50 * time.Millisecond)
	elapsed := time.Since(start)
	close(blocker)
	if len(timedOut) != 4 {
		t.Fatalf("timed out pools = %v, want all four", timedOut)
	}
	if elapsed >= 150*time.Millisecond {
		t.Fatalf("parallel pool stop took %v, want one timeout window", elapsed)
	}
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
	time.Sleep(20 * time.Millisecond)
	// Cancel ctx so the closure's select picks ctx.Done instead of blocked channel send
	cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestRunSessionRestartInMainLoop(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)

		time.Sleep(50 * time.Millisecond)
		// Send restart event — exercised in the main loop select
		srv.sendEvent("restart", json.RawMessage(`{}`))
		time.Sleep(200 * time.Millisecond)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
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
		time.Sleep(200 * time.Millisecond)
		close(stopDrain)
		srv.close()
	}()

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	if err == nil {
		t.Error("expected error after server close")
	}
}

func TestRunAgentCancelDuringRetry(t *testing.T) {
	origRetry := initialRetryDelay
	defer func() { initialRetryDelay = origRetry }()
	initialRetryDelay = 100 * time.Millisecond

	// Connects to a port nothing listens on, then cancel during retry delay
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runAgent(ctx, "ws://127.0.0.1:1", "token", nil)
		close(done)
	}()

	// Wait for first connection attempt to fail and retry delay to start
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// runAgent returned after cancel during retry
	case <-time.After(time.Second):
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

	err := runSession(context.Background(), "ws://"+srv.addr(), "token", nil)
	if err == nil {
		t.Error("expected error from write or read failure")
	}
	// Either "read:" or "write:" error is acceptable
}

// ---------------------------------------------------------------------------
// log capture harness
// ---------------------------------------------------------------------------

// agtLogWaiter unblocks once need records containing sub have been logged.
type agtLogWaiter struct {
	sub   string
	need  int
	seen  int
	fired bool
	done  chan struct{}
}

// agtLogSink is a slog.Handler that records every log line so tests can assert
// on the branches the agent reports only through logs. It can also gate the
// goroutine that logs a chosen message, which gives tests a precise point
// inside runSession to interfere from the outside.
type agtLogSink struct {
	mu            sync.Mutex
	lines         []string
	waiters       []*agtLogWaiter
	gateMsg       string
	gateHit       chan struct{}
	gateHitClosed bool
	gateRelease   chan struct{}
}

// agtCaptureLogs installs a recording slog handler for the duration of the test.
func agtCaptureLogs(t *testing.T) *agtLogSink {
	t.Helper()
	sink := &agtLogSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() {
		sink.ungate()
		slog.SetDefault(prev)
	})
	return sink
}

func (s *agtLogSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *agtLogSink) WithAttrs([]slog.Attr) slog.Handler { return s }

func (s *agtLogSink) WithGroup(string) slog.Handler { return s }

func (s *agtLogSink) Handle(_ context.Context, r slog.Record) error {
	var line strings.Builder
	line.WriteString(r.Level.String())
	line.WriteByte(' ')
	line.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		line.WriteByte(' ')
		line.WriteString(a.Key)
		line.WriteByte('=')
		line.WriteString(a.Value.String())
		return true
	})
	text := line.String()

	var wait chan struct{}
	s.mu.Lock()
	s.lines = append(s.lines, text)
	for _, w := range s.waiters {
		if w.fired || !strings.Contains(text, w.sub) {
			continue
		}
		w.seen++
		if w.seen >= w.need {
			w.fired = true
			close(w.done)
		}
	}
	if s.gateRelease != nil && r.Message == s.gateMsg {
		if !s.gateHitClosed {
			s.gateHitClosed = true
			close(s.gateHit)
		}
		wait = s.gateRelease
	}
	s.mu.Unlock()

	if wait != nil {
		<-wait
	}
	return nil
}

// gateOn parks whichever goroutine logs msg until release is called. hit is
// closed once the gate is reached.
func (s *agtLogSink) gateOn(msg string) (hit <-chan struct{}, release func()) {
	s.mu.Lock()
	s.gateMsg = msg
	s.gateHit = make(chan struct{})
	s.gateHitClosed = false
	s.gateRelease = make(chan struct{})
	h := s.gateHit
	s.mu.Unlock()
	return h, s.ungate
}

func (s *agtLogSink) ungate() {
	s.mu.Lock()
	rel := s.gateRelease
	s.gateRelease = nil
	s.gateMsg = ""
	s.mu.Unlock()
	if rel != nil {
		close(rel)
	}
}

func (s *agtLogSink) expect(sub string, need int) <-chan struct{} {
	w := &agtLogWaiter{sub: sub, need: need, done: make(chan struct{})}
	s.mu.Lock()
	for _, line := range s.lines {
		if strings.Contains(line, sub) {
			w.seen++
		}
	}
	if w.seen >= w.need {
		w.fired = true
		close(w.done)
	}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()
	return w.done
}

func (s *agtLogSink) waitFor(t *testing.T, sub string) {
	t.Helper()
	s.waitForCount(t, sub, 1)
}

func (s *agtLogSink) waitForCount(t *testing.T, sub string, need int) {
	t.Helper()
	select {
	case <-s.expect(sub, need):
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for %d log record(s) containing %q\nlogged:\n%s", need, sub, s.dump())
	}
}

func (s *agtLogSink) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.lines {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

func (s *agtLogSink) dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// ---------------------------------------------------------------------------
// websocket server harness (driven from the test goroutine so assertions and
// t.Fatalf stay on the right goroutine)
// ---------------------------------------------------------------------------

func agtListen(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.(*net.TCPListener)
}

func agtURL(ln net.Listener) string { return "ws://" + ln.Addr().String() }

// agtUpgrade completes the WebSocket handshake for one accepted connection.
func agtUpgrade(t *testing.T, conn *net.TCPConn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read upgrade request: %v", err)
	}
	accept := computeAcceptKey(extractWSKey(string(buf[:n])))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		t.Fatalf("write upgrade response: %v", err)
	}
}

// agtAcceptRaw accepts one connection and completes the handshake without
// reading the channel join frame.
func agtAcceptRaw(t *testing.T, ln *net.TCPListener) *net.TCPConn {
	t.Helper()
	_ = ln.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	conn := c.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	agtUpgrade(t, conn)
	return conn
}

// agtReadJoin reads the channel join frame and returns the topic the agent used.
func agtReadJoin(t *testing.T, conn *net.TCPConn) string {
	t.Helper()
	data, err := readMaskedFrame(conn)
	if err != nil {
		t.Fatalf("read join frame: %v", err)
	}
	var join channelMsg
	if err := json.Unmarshal(data, &join); err != nil {
		t.Fatalf("unmarshal join frame: %v", err)
	}
	if join.Event != "phx_join" {
		t.Fatalf("first frame event = %q, want phx_join", join.Event)
	}
	return join.Topic
}

// agtAccept accepts one agent connection, completes the handshake and replies
// to the channel join with status ok. It returns the connection and topic.
func agtAccept(t *testing.T, ln *net.TCPListener) (*net.TCPConn, string) {
	t.Helper()
	conn := agtAcceptRaw(t, ln)
	topic := agtReadJoin(t, conn)
	reply, err := json.Marshal(channelMsg{
		Topic:   topic,
		Event:   "phx_reply",
		Payload: json.RawMessage(`{"status":"ok"}`),
		Ref:     strPtr("1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(makeTextFrame(reply)); err != nil {
		t.Fatalf("write join reply: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, topic
}

// agtSendEvent pushes a channel event to the connected agent.
func agtSendEvent(t *testing.T, conn net.Conn, topic, event string, payload json.RawMessage) {
	t.Helper()
	msg, err := json.Marshal(channelMsg{Topic: topic, Event: event, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(makeTextFrame(msg)); err != nil {
		t.Fatalf("send %q: %v", event, err)
	}
}

// agtReadFrames decodes the agent's outbound frames in the background until the
// connection dies.
func agtReadFrames(conn net.Conn) <-chan channelMsg {
	out := make(chan channelMsg, 512)
	go func() {
		defer close(out)
		for {
			data, err := readMaskedFrame(conn)
			if err != nil {
				return
			}
			var msg channelMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			select {
			case out <- msg:
			default:
			}
		}
	}()
	return out
}

// agtWaitEvent returns the next outbound frame carrying event, skipping others.
func agtWaitEvent(t *testing.T, msgs <-chan channelMsg, event string) channelMsg {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case msg, ok := <-msgs:
			if !ok {
				t.Fatalf("connection closed before a %q frame arrived", event)
			}
			if msg.Event == event {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a %q frame", event)
		}
	}
}

// agtDecodeBinary unwraps the {"binary": ...} payload of an outbound frame.
func agtDecodeBinary(t *testing.T, payload json.RawMessage, msg proto.Message) {
	t.Helper()
	var wrapper struct {
		Binary string `json:"binary"`
	}
	if err := json.Unmarshal(payload, &wrapper); err != nil {
		t.Fatalf("unmarshal payload wrapper: %v", err)
	}
	bin, err := base64.StdEncoding.DecodeString(wrapper.Binary)
	if err != nil {
		t.Fatalf("decode base64 payload: %v", err)
	}
	if err := proto.Unmarshal(bin, msg); err != nil {
		t.Fatalf("unmarshal protobuf payload: %v", err)
	}
}

// agtReset aborts a connection with a TCP RST so the peer's pending writes and
// reads fail immediately instead of draining a graceful close.
func agtReset(conn *net.TCPConn) {
	_ = conn.SetLinger(0)
	_ = conn.Close()
}

// agtTrap builds a valid trap, optionally padded so a single trap message is
// larger than any socket buffer.
func agtTrap(sourceIP string, pad int) *pb.SnmpTrap {
	trap := &pb.SnmpTrap{
		SourceIp:  sourceIP,
		Version:   2,
		TrapOid:   "1.3.6.1.6.3.1.1.5.3",
		Timestamp: 1,
	}
	if pad > 0 {
		trap.Varbinds = map[string]string{"1.3.6.1.2.1.1.1.0": strings.Repeat("x", pad)}
	}
	return trap
}

// agtFillerFrame builds an ignorable inbound frame of roughly size bytes.
func agtFillerFrame(size int) []byte {
	msg, _ := json.Marshal(struct {
		Topic   string          `json:"topic"`
		Event   string          `json:"event"`
		Payload json.RawMessage `json:"payload"`
		Pad     string          `json:"pad"`
	}{Topic: "phoenix", Event: "phx_reply", Payload: json.RawMessage(`{}`), Pad: strings.Repeat("f", size)})
	return makeTextFrame(msg)
}

// agtShortHeartbeats disables both heartbeats so they cannot interfere with
// tests that count outbound frames or fill the write channel deliberately.
func agtSilenceHeartbeats(t *testing.T) {
	t.Helper()
	origHB, origCHB := heartbeatInterval, channelHeartbeatInterval
	heartbeatInterval = time.Hour
	channelHeartbeatInterval = time.Hour
	t.Cleanup(func() {
		heartbeatInterval = origHB
		channelHeartbeatInterval = origCHB
	})
}

// ---------------------------------------------------------------------------
// join handshake failures
// ---------------------------------------------------------------------------

func TestAgtRunSessionJoinReplyWrongEvent(t *testing.T) {
	ln := agtListen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := c.(*net.TCPConn)
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		accept := computeAcceptKey(extractWSKey(string(buf[:n])))
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"))
		if _, err := readMaskedFrame(conn); err != nil {
			return
		}
		reply, _ := json.Marshal(channelMsg{
			Topic:   "agent:whatever",
			Event:   "phx_error",
			Payload: json.RawMessage(`{"status":"ok"}`),
			Ref:     strPtr("1"),
		})
		_, _ = conn.Write(makeTextFrame(reply))
		_, _ = readMaskedFrame(conn) // hold the connection open until the agent leaves
	}()

	err := runSession(context.Background(), agtURL(ln), "token", nil)
	if err == nil || !strings.Contains(err.Error(), "expected phx_reply, got phx_error") {
		t.Fatalf("runSession error = %v, want 'expected phx_reply, got phx_error'", err)
	}
}

func TestAgtRunSessionJoinReplyBadStatusPayload(t *testing.T) {
	ln := agtListen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := c.(*net.TCPConn)
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		accept := computeAcceptKey(extractWSKey(string(buf[:n])))
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"))
		if _, err := readMaskedFrame(conn); err != nil {
			return
		}
		// Payload is a JSON array, so decoding it into the status struct fails.
		reply, _ := json.Marshal(channelMsg{
			Topic:   "agent:whatever",
			Event:   "phx_reply",
			Payload: json.RawMessage(`[1,2,3]`),
			Ref:     strPtr("1"),
		})
		_, _ = conn.Write(makeTextFrame(reply))
		_, _ = readMaskedFrame(conn)
	}()

	err := runSession(context.Background(), agtURL(ln), "token", nil)
	if err == nil || !strings.Contains(err.Error(), "join reply payload") {
		t.Fatalf("runSession error = %v, want 'join reply payload'", err)
	}
}

func TestAgtRunSessionJoinWriteFails(t *testing.T) {
	logs := agtCaptureLogs(t)
	// Park the agent right after the WebSocket handshake, before it writes the
	// channel join, then kill the connection under it.
	hit, release := logs.gateOn("connected")
	defer release()

	ln := agtListen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := c.(*net.TCPConn)
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		accept := computeAcceptKey(extractWSKey(string(buf[:n])))
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"))
		<-hit
		cancel()
		agtReset(conn)
		release()
	}()

	err := runSession(ctx, agtURL(ln), "token", nil)
	if err == nil || !strings.Contains(err.Error(), "send join") {
		t.Fatalf("runSession error = %v, want 'send join'", err)
	}
}

// ---------------------------------------------------------------------------
// trap forwarding
// ---------------------------------------------------------------------------

func TestAgtRunSessionTrapForwarding(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	ln := agtListen(t)
	traps := make(chan *pb.SnmpTrap, 4)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", traps) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)

	traps <- agtTrap("10.9.9.9", 0)
	frame := agtWaitEvent(t, msgs, "trap")
	var got pb.SnmpTrap
	agtDecodeBinary(t, frame.Payload, &got)
	if got.SourceIp != "10.9.9.9" || got.TrapOid != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("forwarded trap = %+v, want source 10.9.9.9", &got)
	}
	if frame.Topic != topic {
		t.Errorf("trap frame topic = %q, want %q", frame.Topic, topic)
	}

	// A nil trap is dropped instead of being forwarded or crashing the session.
	traps <- nil
	logs.waitFor(t, "ignoring nil snmp trap")

	// A closed listener channel detaches the trap arm and keeps the session up.
	close(traps)
	logs.waitFor(t, "snmp trap listener stopped")

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
	if n := len(msgs); n > 0 {
		for msg := range msgs {
			if msg.Event == "trap" {
				t.Errorf("nil trap was forwarded as %+v", msg)
			}
		}
	}
}

func TestAgtRunSessionTrapMarshalFailure(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	ln := agtListen(t)
	traps := make(chan *pb.SnmpTrap, 4)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", traps) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)

	// Invalid UTF-8 in a proto3 string field makes protobuf marshalling fail.
	traps <- &pb.SnmpTrap{SourceIp: "\xff\xfe", TrapOid: "1.2.3"}
	logs.waitFor(t, "marshal protobuf")

	// The session survives and still forwards the next valid trap.
	traps <- agtTrap("10.0.0.7", 0)
	frame := agtWaitEvent(t, msgs, "trap")
	var got pb.SnmpTrap
	agtDecodeBinary(t, frame.Payload, &got)
	if got.SourceIp != "10.0.0.7" {
		t.Fatalf("forwarded trap source = %q, want 10.0.0.7 (the unmarshalable trap must be dropped)", got.SourceIp)
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
}

// ---------------------------------------------------------------------------
// LLDP topology results
// ---------------------------------------------------------------------------

func TestAgtRunSessionLldpTopologyResult(t *testing.T) {
	agtSilenceHeartbeats(t)

	origDial := snmpDial
	defer func() { snmpDial = origDial }()
	snmpDial = func(*pb.SnmpDevice) (snmpQuerier, func(), error) {
		return nil, nil, fmt.Errorf("refused")
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)

	agtSendEvent(t, conn, topic, "jobs", makeJobPayload(&pb.AgentJob{
		JobId:      "lldp-1",
		DeviceId:   "dev-lldp",
		JobType:    pb.JobType_LLDP_TOPOLOGY,
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
	}))

	frame := agtWaitEvent(t, msgs, "lldp_topology_result")
	var got pb.LldpTopologyResult
	agtDecodeBinary(t, frame.Payload, &got)
	if got.DeviceId != "dev-lldp" || got.JobId != "lldp-1" {
		t.Fatalf("lldp result = %+v, want device dev-lldp job lldp-1", &got)
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
}

func TestAgtDispatchJobLldpTopology(t *testing.T) {
	origDial := snmpDial
	defer func() { snmpDial = origDial }()
	snmpDial = func(*pb.SnmpDevice) (snmpQuerier, func(), error) {
		return nil, nil, fmt.Errorf("refused")
	}

	lldpCh := make(chan *pb.LldpTopologyResult, 1)
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId:      "lldp-2",
		DeviceId:   "dev-2",
		JobType:    pb.JobType_LLDP_TOPOLOGY,
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.2"},
	}, testPools(t),
		make(chan *pb.SnmpResult, 1), make(chan *pb.MikrotikResult, 1),
		make(chan *pb.CredentialTestResult, 1), make(chan *pb.MonitoringCheck, 1),
		make(chan *pb.CheckResult, 1), lldpCh)

	select {
	case result := <-lldpCh:
		if result.JobId != "lldp-2" || result.DeviceId != "dev-2" {
			t.Fatalf("result = %+v, want job lldp-2 device dev-2", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LLDP job never reached the SNMP pool")
	}
}

// ---------------------------------------------------------------------------
// write channel saturation
// ---------------------------------------------------------------------------

func TestAgtRunSessionWriteChannelFull(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	// Overflowing the write channel cancels the session context, and the reader
	// wakes on that same cancellation, so the session loop reports either the
	// cancelled session or the reader's context error. Retry until the session
	// context is the report that wins.
	const attempts = 20
	var lastErr error
	for attempt := range attempts {
		ln := agtListen(t)
		traps := make(chan *pb.SnmpTrap, 512)
		// One oversized trap parks the writer goroutine mid-write (the server
		// never reads), then the small traps pile up until writeCh (cap 256)
		// overflows.
		traps <- agtTrap("10.0.0.1", 2<<20)
		for range 300 {
			traps <- agtTrap("10.0.0.2", 0)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runSession(ctx, agtURL(ln), "token", traps) }()

		conn, _ := agtAccept(t, ln)
		_ = conn.SetReadBuffer(4096)

		select {
		case lastErr = <-done:
		case <-time.After(30 * time.Second):
			cancel()
			t.Fatalf("runSession never gave up on the saturated write channel\nlogged:\n%s", logs.dump())
		}
		cancel()
		_ = ln.Close()

		if lastErr == nil {
			t.Fatal("runSession returned nil despite the saturated write channel")
		}
		if !logs.has("write channel full, reconnecting event=trap") {
			t.Fatalf("expected a 'write channel full' report for the trap event\nlogged:\n%s", logs.dump())
		}
		if strings.Contains(lastErr.Error(), "session cancelled") {
			t.Logf("session loop reported the cancelled session on attempt %d", attempt+1)
			return
		}
	}
	t.Fatalf("session loop never reported the cancelled session in %d attempts; last error: %v", attempts, lastErr)
}

func TestAgtRunSessionChannelHeartbeatWriteChannelFull(t *testing.T) {
	logs := agtCaptureLogs(t)
	origHB, origCHB := heartbeatInterval, channelHeartbeatInterval
	defer func() {
		heartbeatInterval = origHB
		channelHeartbeatInterval = origCHB
	}()
	heartbeatInterval = time.Hour // keep the protobuf heartbeat out of the way
	channelHeartbeatInterval = 200 * time.Microsecond

	ln := agtListen(t)
	traps := make(chan *pb.SnmpTrap, 1)
	traps <- agtTrap("10.0.0.1", 2<<20) // parks the writer goroutine

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runSession(ctx, agtURL(ln), "token", traps) }()

	conn, _ := agtAccept(t, ln)
	_ = conn.SetReadBuffer(4096)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runSession returned nil despite the saturated write channel")
		}
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatalf("channel heartbeats never overflowed the write channel\nlogged:\n%s", logs.dump())
	}
	if !logs.has("write channel full, reconnecting event=heartbeat") {
		t.Errorf("expected a 'write channel full' report for the channel heartbeat\nlogged:\n%s", logs.dump())
	}
}

// ---------------------------------------------------------------------------
// teardown with a stuck worker pool
// ---------------------------------------------------------------------------

func TestAgtRunSessionPoolShutdownTimeout(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	origTimeout := poolShutdownTimeout
	defer func() { poolShutdownTimeout = origTimeout }()
	poolShutdownTimeout = 20 * time.Millisecond

	blocked := make(chan struct{})
	defer close(blocked)
	entered := make(chan struct{}, 1)

	origDial := mikrotikDial
	defer func() { mikrotikDial = origDial }()
	mikrotikDial = func(context.Context, string, uint32, string, string, bool) (*mikrotikClient, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blocked
		return nil, fmt.Errorf("released")
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	agtSendEvent(t, conn, topic, "jobs", makeJobPayload(&pb.AgentJob{
		JobId:          "mt-stuck",
		JobType:        pb.JobType_MIKROTIK,
		MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
	}))

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("mikrotik job never started")
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
	if !logs.has("worker pool shutdown timed out, abandoning in-flight jobs pool=mikrotik") {
		t.Errorf("expected the mikrotik pool to be reported as abandoned\nlogged:\n%s", logs.dump())
	}
}

// ---------------------------------------------------------------------------
// stalled session: reader blocked handing off, writer blocked mid-write
// ---------------------------------------------------------------------------

// agtStallWriteTimeout is how long a test server write may block before we
// conclude the agent stopped reading the socket.
const agtStallWriteTimeout = 250 * time.Millisecond

type agtStalledSession struct {
	conn      *net.TCPConn
	topic     string
	done      <-chan error
	cancel    context.CancelFunc
	release   func()
	updateURL string
	updateSum string
}

// agtStallSession drives a live session into a fully stalled state:
//   - the writer goroutine is blocked mid-write on an oversized trap, because
//     the test server stops reading after the join,
//   - the session loop is parked inside a self-update,
//   - msgCh (cap 100) is full, so the reader goroutine is blocked handing its
//     next message to the session loop instead of watching the socket.
//
// trapSeq is the number of traps the calling test already forwarded, so the
// wait latches onto this session's trap.
func agtStallSession(t *testing.T, logs *agtLogSink, trapSeq int) *agtStalledSession {
	t.Helper()

	s := &agtStalledSession{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	s.release = func() { releaseOnce.Do(func() { close(release) }) }

	origUpdate := doSelfUpdate
	doSelfUpdate = func(_ context.Context, url, checksum string) error {
		s.updateURL, s.updateSum = url, checksum
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() {
		doSelfUpdate = origUpdate
		s.release()
	})

	ln := agtListen(t)
	traps := make(chan *pb.SnmpTrap, 1)
	traps <- agtTrap("10.0.0.1", 2<<20)

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	done := make(chan error, 1)
	go func() { done <- runSession(ctx, agtURL(ln), "token", traps) }()
	s.done = done

	conn, topic := agtAccept(t, ln)
	s.conn, s.topic = conn, topic
	_ = conn.SetReadBuffer(4096)
	logs.waitForCount(t, "sent snmp trap", trapSeq+1)

	agtSendEvent(t, conn, topic, "update", json.RawMessage(`{"url":"https://example.invalid/agent","checksum":"deadbeef"}`))
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		cancel()
		s.release()
		t.Fatalf("update was never dispatched\nlogged:\n%s", logs.dump())
	}

	filler := agtFillerFrame(8 << 10)
	stalled := false
	for range 4000 {
		_ = conn.SetWriteDeadline(time.Now().Add(agtStallWriteTimeout))
		if _, err := conn.Write(filler); err != nil {
			stalled = true
			break
		}
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if !stalled {
		cancel()
		s.release()
		t.Fatal("agent kept reading the socket; msgCh never filled")
	}
	return s
}

func TestAgtRunSessionReaderStopsWhileHandingOffMessage(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	s := agtStallSession(t, logs, 0)
	s.cancel()  // the reader is blocked on the hand-off: it must exit on cancel
	s.release() // let the session loop finish the update and return

	err := <-s.done
	if err != nil && strings.Contains(err.Error(), "read:") {
		t.Fatalf("runSession error = %v; the blocked reader should exit on session cancel, not report a read error", err)
	}
	if s.updateURL != "https://example.invalid/agent" || s.updateSum != "deadbeef" {
		t.Errorf("self-update args = (%q, %q), want the payload url and checksum", s.updateURL, s.updateSum)
	}
}

func TestAgtRunSessionReportsWriteError(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	// Resetting the connection fails the blocked writer while the blocked reader
	// stays off the socket, so the session loop can report the write error. It
	// still picks at random between that error, the cancelled session context
	// the writer sets right after, and the queued inbound messages, so retry
	// until the write error is the one that wins.
	const attempts = 40
	var lastErr error
	for attempt := range attempts {
		s := agtStallSession(t, logs, attempt)
		agtReset(s.conn)
		s.release()

		select {
		case lastErr = <-s.done:
		case <-time.After(30 * time.Second):
			s.cancel()
			t.Fatal("runSession did not return after the connection was reset")
		}
		s.cancel()

		if lastErr == nil {
			t.Fatal("runSession returned nil after the connection was reset")
		}
		if strings.Contains(lastErr.Error(), "write:") {
			t.Logf("writer error reached the session loop on attempt %d", attempt+1)
			if !logs.has("websocket write") {
				t.Errorf("expected a 'websocket write' report\nlogged:\n%s", logs.dump())
			}
			return
		}
	}
	t.Fatalf("session loop never reported the writer error in %d attempts; last error: %v", attempts, lastErr)
}

// ---------------------------------------------------------------------------
// reconnect loop
// ---------------------------------------------------------------------------

func TestAgtRunAgentResetsBackoffAfterLongSession(t *testing.T) {
	logs := agtCaptureLogs(t)

	origThreshold, origRetry := successfulConnectionThreshold, initialRetryDelay
	defer func() {
		successfulConnectionThreshold = origThreshold
		initialRetryDelay = origRetry
	}()
	successfulConnectionThreshold = time.Nanosecond // every session counts as stable
	initialRetryDelay = 20 * time.Millisecond

	ln := agtListen(t)
	connected := make(chan time.Time, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case connected <- time.Now():
			default:
			}
			agtReset(c.(*net.TCPConn))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	agentDone := make(chan struct{})
	go func() {
		runAgent(ctx, agtURL(ln), "token", nil)
		close(agentDone)
	}()

	const want = 6
	stamps := make([]time.Time, 0, want)
	for len(stamps) < want {
		select {
		case ts := <-connected:
			stamps = append(stamps, ts)
		case <-time.After(15 * time.Second):
			cancel()
			<-agentDone
			t.Fatalf("only %d of %d reconnects happened", len(stamps), want)
		}
	}
	cancel()
	<-agentDone

	// With the backoff reset every gap stays near initialRetryDelay; without it
	// the gaps would double (20ms, 40ms, 80ms, 160ms, ...).
	for i := 1; i < len(stamps); i++ {
		if gap := stamps[i].Sub(stamps[i-1]); gap > 130*time.Millisecond {
			t.Fatalf("reconnect gap %d = %v, want the backoff to stay reset near %v", i, gap, initialRetryDelay)
		}
	}
	if !logs.has("resetting reconnect backoff after successful session") {
		t.Errorf("expected the backoff reset to be reported\nlogged:\n%s", logs.dump())
	}
}

func TestAgtRunAgentStopsWhenCancelledDuringSession(t *testing.T) {
	logs := agtCaptureLogs(t)

	origRetry := initialRetryDelay
	defer func() { initialRetryDelay = origRetry }()
	initialRetryDelay = time.Hour // any retry sleep would hang the test

	ln := agtListen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		cancel() // cancelled while the session is still connecting
		agtReset(c.(*net.TCPConn))
	}()

	agentDone := make(chan struct{})
	go func() {
		runAgent(ctx, agtURL(ln), "token", nil)
		close(agentDone)
	}()

	select {
	case <-agentDone:
	case <-time.After(15 * time.Second):
		t.Fatal("runAgent kept retrying after its context was cancelled")
	}
	if logs.has("reconnecting delay=") {
		t.Errorf("runAgent scheduled a reconnect despite the cancelled context\nlogged:\n%s", logs.dump())
	}
}

func TestAgtRunAgentReconnectsImmediatelyAfterRestart(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	origThreshold, origRetry := successfulConnectionThreshold, initialRetryDelay
	defer func() {
		successfulConnectionThreshold = origThreshold
		initialRetryDelay = origRetry
	}()
	successfulConnectionThreshold = time.Hour // only the restart branch may reset
	initialRetryDelay = 3 * time.Second       // a backoff sleep would be obvious

	ln := agtListen(t)
	ctx, cancel := context.WithCancel(context.Background())
	agentDone := make(chan struct{})
	go func() {
		runAgent(ctx, agtURL(ln), "token", nil)
		close(agentDone)
	}()

	conn, topic := agtAccept(t, ln)
	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	restarted := time.Now()

	conn2, _ := agtAccept(t, ln)
	elapsed := time.Since(restarted)
	cancel()
	<-agentDone
	_ = conn2.Close()

	if elapsed >= initialRetryDelay {
		t.Fatalf("reconnect took %v, want an immediate retry well under %v", elapsed, initialRetryDelay)
	}
	if !logs.has("restart requested, reconnecting immediately") {
		t.Errorf("expected the immediate reconnect to be reported\nlogged:\n%s", logs.dump())
	}
}

// ---------------------------------------------------------------------------
// backoff arithmetic
// ---------------------------------------------------------------------------

func TestAgtNextBackoffEdgeCases(t *testing.T) {
	origRetry := initialRetryDelay
	defer func() { initialRetryDelay = origRetry }()
	initialRetryDelay = time.Second

	for _, current := range []time.Duration{0, -time.Second} {
		got := nextBackoff(current, time.Minute)
		if got < 2*time.Second || got >= 2*time.Second+500*time.Millisecond {
			t.Errorf("nextBackoff(%v, 1m) = %v, want a normalized [2s, 2.5s) delay", current, got)
		}
	}

	// A cap below 4ns leaves no room for jitter, so the delay is exact.
	if got := nextBackoff(time.Nanosecond, 2*time.Nanosecond); got != 2*time.Nanosecond {
		t.Errorf("nextBackoff(1ns, 2ns) = %v, want exactly 2ns", got)
	}
}

func TestPropAgtNextBackoff(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		current := time.Duration(rapid.Int64Range(int64(-time.Second), int64(60*time.Second)).Draw(t, "current"))
		maxDelay := time.Duration(rapid.Int64Range(int64(time.Millisecond), int64(60*time.Second)).Draw(t, "maxDelay"))

		// nextBackoff normalizes a non-positive delay to initialRetryDelay,
		// doubles it, caps it and then adds strictly less than 25% jitter.
		base := current
		if base <= 0 {
			base = initialRetryDelay
		}
		want := base * 2
		if want > maxDelay {
			want = maxDelay
		}

		got := nextBackoff(current, maxDelay)
		if got < 0 {
			t.Fatalf("nextBackoff(%v, %v) = %v, want a non-negative delay", current, maxDelay, got)
		}
		jitter := want / 4
		if jitter <= 0 {
			if got != want {
				t.Fatalf("nextBackoff(%v, %v) = %v, want exactly %v (no room for jitter)", current, maxDelay, got, want)
			}
			return
		}
		if got < want || got >= want+jitter {
			t.Fatalf("nextBackoff(%v, %v) = %v, want in [%v, %v)", current, maxDelay, got, want, want+jitter)
		}
	})
}

func TestPropAgtZeroBytes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOf(rapid.Byte()).Draw(t, "bytes")
		n := len(b)

		zeroBytes(b)
		if len(b) != n {
			t.Fatalf("zeroBytes changed the length: %d, want %d", len(b), n)
		}
		for i, v := range b {
			if v != 0 {
				t.Fatalf("byte %d = %d after zeroBytes, want 0", i, v)
			}
		}

		zeroBytes(b) // idempotent
		if len(b) != n {
			t.Fatalf("second zeroBytes changed the length: %d, want %d", len(b), n)
		}
		for i, v := range b {
			if v != 0 {
				t.Fatalf("byte %d = %d after a second zeroBytes, want 0", i, v)
			}
		}
	})
}

func TestPropAgtDecodeBinaryPayload(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(0, 4).Draw(t, "jobs")
		id := rapid.StringMatching(`[a-zA-Z0-9_-]{0,16}`)
		list := &pb.AgentJobList{}
		for i := range count {
			list.Jobs = append(list.Jobs, &pb.AgentJob{
				JobId:    id.Draw(t, fmt.Sprintf("job_id_%d", i)),
				DeviceId: id.Draw(t, fmt.Sprintf("device_id_%d", i)),
			})
		}

		bin, err := proto.Marshal(list)
		if err != nil {
			t.Fatalf("marshal job list: %v", err)
		}
		payload, err := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}

		var got pb.AgentJobList
		if !decodeBinaryPayload("jobs", payload, &got) {
			t.Fatalf("decodeBinaryPayload rejected a well-formed payload for %v", list)
		}
		if !proto.Equal(list, &got) {
			t.Fatalf("decoded %v, want %v", &got, list)
		}

		// Anything outside the base64 alphabet must be rejected, not panic.
		junk := rapid.SliceOfN(rapid.SampledFrom([]byte("!@#$%^&*()~ ")), 1, 8).Draw(t, "junk")
		bad, err := json.Marshal(map[string]string{"binary": string(junk)})
		if err != nil {
			t.Fatalf("marshal junk payload: %v", err)
		}
		var out pb.AgentJobList
		if decodeBinaryPayload("jobs", bad, &out) {
			t.Fatalf("decodeBinaryPayload accepted %q as base64", junk)
		}
	})
}
