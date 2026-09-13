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
	"reflect"
	"runtime"
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
		Ref:     new("1"),
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
	ctx, cancel := context.WithCancel(context.Background())
	p := &jobPools{
		snmp:     newWorkerPool(4),
		mikrotik: newWorkerPool(4),
		ping:     newWorkerPool(4),
		checks:   newWorkerPool(4),
		notices:  make(chan outbound, overloadNoticeQueueSize),
	}
	p.scheduler = newRecurringScheduler(ctx, realScheduleClock{})
	t.Cleanup(func() {
		cancel()
		p.scheduler.cancelAll()
		p.snmp.stop()
		p.mikrotik.stop()
		p.ping.stop()
		p.checks.stop()
		if !p.scheduler.wait(time.Second) {
			t.Error("scheduler did not stop")
		}
	})
	return p
}

// newResultQueue supplies an active agent context to tests that do not need to
// distinguish session cancellation from process shutdown.
func newResultQueue(size int) *resultQueue {
	return newResultQueueForAgent(context.Background(), size)
}

// testQueue returns a buffered result queue for tests that only need to see
// what an executor published.
func testQueue() *resultQueue {
	return newResultQueue(8)
}

// wantResult reads the next queued result, asserting the event it was
// published under and its protobuf type.
func wantResult[T proto.Message](t *testing.T, out *resultQueue, event string, timeout time.Duration) T {
	t.Helper()
	var zero T
	select {
	case result := <-out.items:
		out.ack()
		if result.event != event {
			t.Fatalf("result event = %q, want %q", result.event, event)
		}
		return decodeQueuedResult[T](t, result)
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for a %q result", event)
		return zero
	}
}

func decodeQueuedResult[T proto.Message](t *testing.T, result outbound) T {
	t.Helper()
	var zero T
	msg := reflect.New(reflect.TypeOf(zero).Elem()).Interface().(T)
	agtDecodeBinary(t, result.payload, msg)
	return msg
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
		out := testQueue()
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "phx_reply", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), out)
		// Just verify it doesn't panic
	})

	t.Run("jobs reconcile recurring work without retaining one-shot polls", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()

		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		out := testQueue()
		pools := testPools(t)
		recurring := makeJobPayload(&pb.AgentJob{
			JobId:      "poll:device-1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		})

		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: recurring}, "agent:test", pools, out)
		_ = wantResult[*pb.SnmpResult](t, out, "result", 500*time.Millisecond)
		if _, ok := pools.scheduler.jobs["poll:device-1"]; !ok {
			t.Fatal("recurring poll was not retained")
		}

		oneShot := makeJobPayload(&pb.AgentJob{
			JobId:      "live_poll:device-1:topic",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: oneShot}, "agent:test", pools, out)
		_ = wantResult[*pb.SnmpResult](t, out, "result", 500*time.Millisecond)
		if len(pools.scheduler.jobs) != 1 {
			t.Fatalf("one-shot poll changed recurring inventory size to %d", len(pools.scheduler.jobs))
		}

		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: makeJobPayload()}, "agent:test", pools, out)
		if len(pools.scheduler.jobs) != 0 {
			t.Fatalf("empty recurring list retained %d jobs", len(pools.scheduler.jobs))
		}
	})

	t.Run("invalid payload json", func(t *testing.T) {
		out := testQueue()
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: json.RawMessage(`not json`)}, "agent:test", testPools(t), out)
		// Should log error but not panic
	})

	t.Run("invalid base64", func(t *testing.T) {
		out := testQueue()
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), out)
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		out := testQueue()
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), out)
	})

	t.Run("restart", func(t *testing.T) {
		out := testQueue()
		shouldEnd, reason := handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "restart", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), out)

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
			out := testQueue()

			shouldEnd, reason := handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: event, Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), out)

			if !shouldEnd {
				t.Fatalf("expected handleMessage to end session for %s", event)
			}
			if reason != errChannelReloaded {
				t.Fatalf("expected reload reason %v for %s, got %v", errChannelReloaded, event, reason)
			}
		}
	})

	t.Run("update runs asynchronously without session cancellation", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() {
			doSelfUpdate = origUpdate
			updateInProgress.Store(false)
		}()
		updateInProgress.Store(false)

		called := make(chan struct{})
		release := make(chan struct{})
		finished := make(chan struct{})
		var calledURL string
		var updateCtx context.Context
		var calls atomic.Int32
		doSelfUpdate = func(ctx context.Context, url, checksum string) error {
			defer close(finished)
			updateCtx = ctx
			calledURL = url
			calls.Add(1)
			close(called)
			<-release
			return nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		returned := make(chan struct{})
		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		pools := testPools(t)
		results := testQueue()
		go func() {
			_, _ = handleMessage(ctx, channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", pools, results)
			close(returned)
		}()

		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("self-update was not started")
		}
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatal("handleMessage blocked on the self-update")
		}

		cancel()
		if updateCtx.Err() != nil {
			t.Fatalf("update context was cancelled with the session: %v", updateCtx.Err())
		}
		if calledURL != "https://example.com/agent" {
			t.Errorf("expected update URL %q, got %q", "https://example.com/agent", calledURL)
		}

		_, _ = handleMessage(ctx, channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", pools, results)
		if got := calls.Load(); got != 1 {
			t.Fatalf("duplicate update started %d downloads, want 1", got)
		}

		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("self-update did not finish after release")
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

		payload, _ := json.Marshal(map[string]string{"checksum": "abc123"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), testQueue())

		if called {
			t.Error("selfUpdate should not be called with empty URL")
		}
	})

	t.Run("update error", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() {
			doSelfUpdate = origUpdate
			updateInProgress.Store(false)
		}()
		updateInProgress.Store(false)

		called := make(chan struct{})
		doSelfUpdate = func(_ context.Context, url, checksum string) error {
			close(called)
			return fmt.Errorf("download failed")
		}

		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent", "checksum": "abc123"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), testQueue())
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("self-update error path was not called")
		}
	})

	t.Run("update missing checksum", func(t *testing.T) {
		origUpdate := doSelfUpdate
		defer func() { doSelfUpdate = origUpdate }()

		called := false
		doSelfUpdate = func(_ context.Context, url, checksum string) error {
			called = true
			return nil
		}

		payload, _ := json.Marshal(map[string]string{"url": "https://example.com/agent"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "update", Payload: payload}, "agent:test", testPools(t), testQueue())

		if called {
			t.Error("selfUpdate should not be called with empty checksum")
		}
	})

	t.Run("unknown event", func(t *testing.T) {
		out := testQueue()
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "some_unknown_event", Payload: json.RawMessage(`{}`)}, "agent:test", testPools(t), out)
		// Should just log and not panic
	})

	t.Run("check_jobs valid", func(t *testing.T) {
		checkList := &pb.CheckList{Checks: []*pb.Check{
			{Id: "c1", CheckType: "tcp", TimeoutMs: 1000,
				Config: &pb.Check_Tcp{Tcp: &pb.TcpCheckConfig{Host: "127.0.0.1", Port: 1}}},
		}}
		bin, _ := proto.Marshal(checkList)
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})

		out := testQueue()
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), out)
		_ = wantResult[*pb.CheckResult](t, out, "check_result", time.Second)
	})

	t.Run("check_jobs invalid json", func(t *testing.T) {
		out := testQueue()
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: json.RawMessage(`not json`)}, "agent:test", testPools(t), out)
		// Should log error but not panic
	})

	t.Run("check_jobs invalid base64", func(t *testing.T) {
		out := testQueue()
		payload, _ := json.Marshal(map[string]string{"binary": "not-base64!!!"})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), out)
		// Should log error but not panic
	})

	t.Run("check_jobs invalid protobuf", func(t *testing.T) {
		out := testQueue()
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF})})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "check_jobs", Payload: payload}, "agent:test", testPools(t), out)
		// Should log error but not panic
	})

	t.Run("discovery_job event", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()

		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		out := testQueue()

		payload := makeJobPayload(&pb.AgentJob{
			JobId:      "d1",
			JobType:    pb.JobType_DISCOVER,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "discovery_job", Payload: payload}, "agent:test", testPools(t), out)
		_ = wantResult[*pb.SnmpResult](t, out, "result", 500*time.Millisecond)
	})

	t.Run("backup_job event", func(t *testing.T) {
		origDial := mikrotikDial
		origSSH := sshBackup
		defer func() { mikrotikDial = origDial; sshBackup = origSSH }()

		sshBackup = func(_ context.Context, ip string, port uint16, username, password string) (string, error) {
			return "/ip address\nadd address=10.0.0.1/24", nil
		}

		out := testQueue()

		payload := makeJobPayload(&pb.AgentJob{
			JobId:          "backup:dev1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", SshPort: 22, Username: "admin", Password: "pass"},
		})
		_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "backup_job", Payload: payload}, "agent:test", testPools(t), out)
		if result := wantResult[*pb.MikrotikResult](t, out, "mikrotik_result", 500*time.Millisecond); result.Error != "" {
			t.Errorf("unexpected error: %s", result.Error)
		}
	})
}

func TestHandleMessageRejectsOversizedPayload(t *testing.T) {
	out := testQueue()

	// Create a binary payload larger than maxJobPayloadBytes
	oversized := make([]byte, maxJobPayloadBytes+1)
	encoded := base64.StdEncoding.EncodeToString(oversized)
	payload, _ := json.Marshal(map[string]string{"binary": encoded})

	_, _ = handleMessage(context.Background(), channelMsg{Topic: "agent:test", Event: "jobs", Payload: payload}, "agent:test", testPools(t), out)

	// Verify no jobs were dispatched
	select {
	case <-out.items:
		t.Error("expected no SNMP result for oversized payload")
	case <-time.After(100 * time.Millisecond):
		// Good - nothing dispatched
	}
}

func TestDecodeBinaryPayloadZeroesDecodedBuffer(t *testing.T) {
	origDecode := decodeBase64
	defer func() { decodeBase64 = origDecode }()

	t.Run("successful protobuf", func(t *testing.T) {
		bin, err := proto.Marshal(&pb.AgentJobList{Jobs: []*pb.AgentJob{{
			JobId: "job-1",
			MikrotikDevice: &pb.MikrotikDevice{
				Password: "sensitive-password",
			},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		decodeBase64 = func(string) ([]byte, error) { return bin, nil }

		var got pb.AgentJobList
		if !decodeBinaryPayload("jobs", json.RawMessage(`{"binary":"ignored"}`), &got) {
			t.Fatal("decodeBinaryPayload rejected a valid protobuf")
		}
		if got.Jobs[0].MikrotikDevice.Password != "sensitive-password" {
			t.Fatal("decoded credentials were corrupted while zeroing the source buffer")
		}
		for i, b := range bin {
			if b != 0 {
				t.Fatalf("decoded byte %d = %d, want zero", i, b)
			}
		}
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		bin := []byte{0xff, 0xff, 0xff}
		decodeBase64 = func(string) ([]byte, error) { return bin, nil }

		var got pb.AgentJobList
		if decodeBinaryPayload("jobs", json.RawMessage(`{"binary":"ignored"}`), &got) {
			t.Fatal("decodeBinaryPayload accepted an invalid protobuf")
		}
		for i, b := range bin {
			if b != 0 {
				t.Fatalf("decoded byte %d = %d after unmarshal failure, want zero", i, b)
			}
		}
	})
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

		out := testQueue()

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:          "mt1",
			JobType:        pb.JobType_MIKROTIK,
			MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
		}, testPools(t), out)

		if result := wantResult[*pb.MikrotikResult](t, out, "mikrotik_result", 500*time.Millisecond); result.Error == "" {
			t.Error("expected error from unreachable device")
		}
	})

	t.Run("TEST_CREDENTIALS", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("refused")
		}

		out := testQueue()

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "tc1",
			JobType:    pb.JobType_TEST_CREDENTIALS,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), out)

		if result := wantResult[*pb.CredentialTestResult](t, out, "credential_test_result", 500*time.Millisecond); result.Success {
			t.Error("expected failure")
		}
	})

	t.Run("PING", func(t *testing.T) {
		origPing := doPing
		defer func() { doPing = origPing }()
		doPing = func(_ context.Context, ip string, timeoutMs int) (float64, error) {
			return 5.5, nil
		}

		out := testQueue()

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "p1",
			JobType:    pb.JobType_PING,
			SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
		}, testPools(t), out)

		if result := wantResult[*pb.MonitoringCheck](t, out, "monitoring_check", 500*time.Millisecond); result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
	})

	t.Run("default SNMP", func(t *testing.T) {
		origDial := snmpDial
		defer func() { snmpDial = origDial }()
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return &mockSnmpQuerier{
				getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
					return &gosnmp.SnmpPacket{}, nil
				},
			}, func() {}, nil
		}

		out := testQueue()

		dispatchJob(context.Background(), &pb.AgentJob{
			JobId:      "s1",
			JobType:    pb.JobType_POLL,
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, testPools(t), out)

		_ = wantResult[*pb.SnmpResult](t, out, "result", 500*time.Millisecond)
	})
}

// A JobType this build does not know about used to fall through to the SNMP
// pool, where it would run against a device config it may not even carry.
func TestDispatchJobDropsUnknownJobType(t *testing.T) {
	logs := agtCaptureLogs(t)
	origDial := snmpDial
	defer func() { snmpDial = origDial }()
	var dials atomic.Int32
	snmpDial = func(context.Context, *pb.SnmpDevice) (snmpQuerier, func(), error) {
		dials.Add(1)
		return nil, nil, errors.New("should not be dialled")
	}

	out := testQueue()
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId:      "unknown-1",
		JobType:    pb.JobType(99),
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, testPools(t), out)

	select {
	case result := <-out.items:
		t.Fatalf("unknown job type produced a %q result", result.event)
	case <-time.After(200 * time.Millisecond):
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("unknown job type reached the SNMP executor %d times", got)
	}
	if !logs.has("job dropped, unknown job type") {
		t.Fatalf("unknown job type was not logged:\n%s", logs.dump())
	}
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

		// Read the join message (masked WebSocket frame) - just consume it
		frameBuf := make([]byte, 4096)
		_, _ = conn.Read(frameBuf)

		// Send phx_error reply as an unmasked text frame
		reply, _ := json.Marshal(channelMsg{
			Topic:   "agent:agent-0",
			Event:   "phx_reply",
			Payload: json.RawMessage(`{"status":"error","response":{"reason":"invalid token"}}`),
			Ref:     new("1"),
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
	if !strings.Contains(err.Error(), "join rejected: error (invalid token)") {
		t.Errorf("expected rejection reason in error, got: %v", err)
	}
}

// TestRunSessionRejectedJoinStartsNoWorkerPools pins B1: the four worker pools
// total 220 goroutines, and creating them before the join reply was validated
// abandoned every one of them on each rejected token - which the reconnect
// loop retries within 10s.
func TestRunSessionRejectedJoinStartsNoWorkerPools(t *testing.T) {
	origTimeout := joinTimeout
	defer func() { joinTimeout = origTimeout }()
	joinTimeout = time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	const sessions = 5
	go func() {
		for range sessions {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Complete the upgrade, then drop the connection so the join fails.
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			accept := computeAcceptKey(extractWSKey(string(buf[:n])))
			_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
				"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().String()
	baseline := runtime.NumGoroutine()
	for range sessions {
		if err := runSession(context.Background(), "ws://"+addr, "revoked-token", nil); err == nil {
			t.Fatal("expected a session error from the dropped join")
		}
	}

	// runSession joins its own reader and writer before returning, so only
	// runtime and library internals can still be winding down.
	const tolerance = 10
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+tolerance && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+tolerance {
		t.Fatalf("goroutines after %d rejected joins = %d, baseline %d: worker pools were started before the join",
			sessions, got, baseline)
	}
}

// TestSessionLoopReportsPublishedErrorOverCancellation pins B5. The reader and
// writer publish their error and only then cancel the session, so both the
// error channel and the cancellation are ready when the loop next runs; Go
// picks a ready case at random, which lost the real disconnect reason about
// half the time. Every iteration must report the read error.
func TestSessionLoopReportsPublishedErrorOverCancellation(t *testing.T) {
	for run := range 20 {
		sessionCtx, cancel := context.WithCancel(context.Background())
		s := &session{
			ctx:        sessionCtx,
			cancel:     cancel,
			writeCh:    make(chan writeRequest, 1),
			msgCh:      make(chan []byte, 1),
			errCh:      make(chan error, 1),
			writeErrCh: make(chan error, 1),
			results:    newResultQueue(1),
		}
		// Exactly what the reader does when the connection fails.
		s.fail(s.errCh, errors.New("connection reset"))

		err := s.loop(context.Background())
		cancel()

		if err == nil {
			t.Fatalf("run %d: loop returned nil, want the read error", run)
		}
		if errors.Is(err, errSessionCancelled) || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("run %d: loop error = %v, want it to name the read failure", run, err)
		}
	}
}

// A cancellation with no published error is the only case that may report the
// generic reason: the session context was cancelled from outside its I/O.
func TestSessionErrWithoutPublishedError(t *testing.T) {
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
	}
	if err := s.sessionErr(); !errors.Is(err, errSessionCancelled) {
		t.Fatalf("sessionErr() = %v, want %v", err, errSessionCancelled)
	}

	s.writeErrCh <- errors.New("broken pipe")
	err := s.sessionErr()
	if err == nil || !strings.HasPrefix(err.Error(), "write:") {
		t.Fatalf("sessionErr() = %v, want the write failure", err)
	}
}

// The write-failure arm of the loop select. In production `fail` publishes the
// error before cancelling, so the cancellation arm and this one are ready
// together and Go picks between them at random - coverage of the write arm was
// a coin flip on whichever integration test closed the connection. Both arms
// return the same "write: ..." error by design, so the behaviour is pinned here
// with the session context left alive: that makes this arm the only ready case,
// and every iteration must surface the published write failure.
func TestSessionLoopReportsWriteFailureWhileContextAlive(t *testing.T) {
	for run := range 20 {
		sessionCtx, cancel := context.WithCancel(context.Background())
		s := &session{
			ctx:        sessionCtx,
			cancel:     cancel,
			writeCh:    make(chan writeRequest, 1),
			errCh:      make(chan error, 1),
			writeErrCh: make(chan error, 1),
			results:    newResultQueue(1),
		}
		// Exactly what the writer does when the connection fails.
		s.fail(s.writeErrCh, errors.New("broken pipe"))

		err := s.loop(context.Background())
		cancel()

		if err == nil {
			t.Fatalf("run %d: loop returned nil, want the write error", run)
		}
		if !strings.HasPrefix(err.Error(), "write:") || !strings.Contains(err.Error(), "broken pipe") {
			t.Fatalf("run %d: loop error = %v, want it to name the write failure", run, err)
		}
	}
}

func TestNewAgentIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		id := newAgentID()
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate agent ID %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestValidateJoinReplyRejectsWrongRef(t *testing.T) {
	for _, ref := range []*string{nil, new("2")} {
		data, err := json.Marshal(channelMsg{
			Event:   "phx_reply",
			Payload: json.RawMessage(`{"status":"ok"}`),
			Ref:     ref,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := validateJoinReply(data); err == nil || !strings.Contains(err.Error(), "unexpected ref") {
			t.Fatalf("validateJoinReply() error = %v, want unexpected ref", err)
		}
	}
}

func TestValidateJoinReplyRejectionReason(t *testing.T) {
	tests := []struct {
		name    string
		payload json.RawMessage
		want    string
	}{
		{
			name:    "reason present",
			payload: json.RawMessage(`{"status":"error","response":{"reason":"invalid token"}}`),
			want:    "join rejected: error (invalid token)",
		},
		{
			name:    "reason absent",
			payload: json.RawMessage(`{"status":"error"}`),
			want:    "join rejected: error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(channelMsg{
				Event:   "phx_reply",
				Payload: tt.payload,
				Ref:     new("1"),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = validateJoinReply(data)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("validateJoinReply() error = %v, want %q", err, tt.want)
			}
		})
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

	out := testQueue()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All dispatch types should hit the "pool full" warning
	dispatchJob(ctx, &pb.AgentJob{
		JobId: "s1", JobType: pb.JobType_POLL, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, out)

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "m1", JobType: pb.JobType_MIKROTIK, MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1"},
	}, p, out)

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "tc1", JobType: pb.JobType_TEST_CREDENTIALS, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, out)

	dispatchJob(ctx, &pb.AgentJob{
		JobId: "p1", JobType: pb.JobType_PING, SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}, p, out)

	close(done)
}

func TestPoolOverloadReportsEveryJobClassWithoutUsingResultSpool(t *testing.T) {
	notices := make(chan outbound, 4)
	p := &jobPools{
		snmp:     newWorkerPool(1),
		mikrotik: newWorkerPool(1),
		ping:     newWorkerPool(1),
		checks:   newWorkerPool(1),
		notices:  notices,
	}
	t.Cleanup(func() { p.snmp.stop(); p.mikrotik.stop(); p.ping.stop(); p.checks.stop() })

	release := make(chan struct{})
	defer close(release)
	fill := func(pool *workerPool) {
		started := make(chan struct{})
		if !pool.submit(context.Background(), func() { close(started); <-release }) {
			t.Fatal("worker pool rejected its first task")
		}
		<-started
		for range cap(pool.tasks) {
			if !pool.submit(context.Background(), func() { <-release }) {
				t.Fatal("worker pool rejected a task before its queue filled")
			}
		}
	}
	fill(p.snmp)
	fill(p.mikrotik)
	fill(p.ping)
	fill(p.checks)

	out := newResultQueue(1)
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId: "snmp-overload", DeviceId: "device-1", JobType: pb.JobType_POLL,
	}, p, out)
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId: "mikrotik-overload", DeviceId: "device-2", JobType: pb.JobType_MIKROTIK,
	}, p, out)
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId: "ping-overload", DeviceId: "device-3", JobType: pb.JobType_PING,
	}, p, out)
	executeCheck(context.Background(), &pb.Check{Id: "check-overload"}, p, out)

	if len(out.items) != 0 || len(out.slots) != 0 {
		t.Fatal("pool rejection notices consumed completed-result spool capacity")
	}
	if !out.enqueue(outbound{event: "real-result"}) {
		t.Fatal("pool rejection notices prevented a real result from being queued")
	}

	want := map[string]string{
		"snmp-overload":     "device-1",
		"mikrotik-overload": "device-2",
		"ping-overload":     "device-3",
		"check-overload":    "",
	}
	for range want {
		notice := <-notices
		if notice.event != "error" {
			t.Fatalf("notice event = %q, want error", notice.event)
		}
		result := decodeQueuedResult[*pb.AgentError](t, notice)
		deviceID, ok := want[result.JobId]
		if !ok {
			t.Fatalf("unexpected rejected job %q", result.JobId)
		}
		if result.DeviceId != deviceID {
			t.Fatalf("rejected job %q device = %q, want %q", result.JobId, result.DeviceId, deviceID)
		}
		if !strings.HasPrefix(result.Message, "worker pool overloaded; retry ") {
			t.Fatalf("rejected job %q error broke the server telemetry contract: %q", result.JobId, result.Message)
		}
		delete(want, result.JobId)
	}

	logs := agtCaptureLogs(t)
	reportPoolRejection(context.Background(), make(chan outbound), "", "dropped-notice", "CHECK")
	if !logs.has("overload notice queue full") {
		t.Fatal("dropped overload notice was not logged")
	}

	invalidNotices := make(chan outbound, 1)
	reportPoolRejection(context.Background(), invalidNotices, "", "\xff", "CHECK")
	if len(invalidNotices) != 0 || !logs.has("marshal protobuf") {
		t.Fatal("unencodable overload notice was not rejected and logged")
	}
}

func TestResultQueueKeepsRetryAheadOfNewerResults(t *testing.T) {
	queue := newResultQueue(2)
	first := outbound{event: "first", payload: json.RawMessage(`{"binary":"first"}`)}
	if !queue.enqueue(first) {
		t.Fatal("result queue rejected its first result")
	}

	inFlight := <-queue.items
	newer := outbound{event: "newer"}
	if !queue.enqueue(newer) {
		t.Fatal("result queue rejected a newer result despite one free slot")
	}
	if queue.enqueue(outbound{event: "overflow"}) {
		t.Fatal("result queue reused the in-flight result's reserved slot")
	}

	queue.retry(inFlight)
	retried, ok := queue.takeRetry()
	if !ok || string(retried.payload) != string(first.payload) {
		t.Fatalf("retried result = %+v, want first result", retried)
	}
	queue.ack()

	if got := <-queue.items; got.event != newer.event {
		t.Fatalf("queued result = %q, want %q after retry", got.event, newer.event)
	}
	queue.ack()
	if _, ok := queue.takeRetry(); ok {
		t.Fatal("retry lane retained an acknowledged result")
	}
}

func TestSendResultUsesAgentContextForDropSeverity(t *testing.T) {
	logs := agtCaptureLogs(t)
	agentCtx, stopAgent := context.WithCancel(context.Background())
	out := newResultQueueForAgent(agentCtx, 0)
	sessionCtx, stopSession := context.WithCancel(context.Background())
	stopSession()

	sendResult(sessionCtx, out, "result", &pb.SnmpResult{JobId: "during-reconnect"}, "during-reconnect")
	if !logs.has("ERROR result buffer full during reconnect - result dropped") {
		t.Fatal("result loss during reconnect was not logged at error level")
	}
	if logs.has("result dropped, agent stopped") {
		t.Fatal("session cancellation was misreported as agent shutdown")
	}

	sendResult(context.Background(), out, "result", &pb.SnmpResult{JobId: "while-connected"}, "while-connected")
	if !logs.has("ERROR result buffer full - agent overloaded") {
		t.Fatal("connected result loss was not reported as agent overload")
	}

	stopAgent()
	sendResult(sessionCtx, out, "result", &pb.SnmpResult{JobId: "during-shutdown"}, "during-shutdown")
	if !logs.has("DEBUG result dropped, agent stopped") {
		t.Fatal("agent shutdown result drop was not logged at debug level")
	}
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
		Ref:     new("1"),
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

func TestRunSessionDeliversResultBufferedAfterDisconnect(t *testing.T) {
	results := newResultQueue(1)
	endedCtx, endSession := context.WithCancel(context.Background())
	endSession()
	sendResult(endedCtx, results, "error", &pb.AgentError{
		DeviceId:  "device-1",
		JobId:     "job-1",
		Message:   "completed while disconnected",
		Timestamp: 1,
	}, "job-1")
	if len(results.items) != 1 {
		t.Fatal("completed result was not buffered after its session ended")
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() {
		done <- runSessionWithResults(context.Background(), agtURL(ln), "token", nil, results)
	}()

	conn, topic := agtAccept(t, ln)
	frame := agtWaitEvent(t, agtReadFrames(conn), "error")
	var got pb.AgentError
	agtDecodeBinary(t, frame.Payload, &got)
	if got.JobId != "job-1" || got.DeviceId != "device-1" {
		t.Fatalf("buffered result = %+v, want job-1 for device-1", &got)
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSessionWithResults error = %v, want %v", err, errRestartRequested)
	}
	if len(results.slots) != 0 {
		t.Fatal("delivered result remained reserved in the reconnect buffer")
	}
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
		// Send invalid JSON - should be logged but not crash
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
					Ref:     new("1"),
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
				Ref:     new("1"),
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

	snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
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

func TestRunSessionDoesNotLogFailedResultAsSent(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	origDial := mikrotikDial
	defer func() { mikrotikDial = origDial }()
	mikrotikDial = func(context.Context, string, uint32, string, string, bool) (*mikrotikClient, error) {
		return nil, errors.New("\xff")
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	agtSendEvent(t, conn, topic, "jobs", makeJobPayload(&pb.AgentJob{
		JobId:          "m-invalid",
		JobType:        pb.JobType_MIKROTIK,
		MikrotikDevice: &pb.MikrotikDevice{Ip: "10.0.0.1", Port: 8728},
	}))
	logs.waitFor(t, "marshal protobuf")
	if logs.has("sent mikrotik result") {
		t.Fatalf("failed result was logged as sent:\n%s", logs.dump())
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
}

func TestRunSessionForwardsManySnmpResults(t *testing.T) {
	origSnmpDial := snmpDial
	defer func() { snmpDial = origSnmpDial }()

	snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
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
		notices:  make(chan outbound, 1),
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

	// Pool is now truly full - submit with cancelled ctx will reliably fail
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := testQueue()
	check := &pb.Check{Id: "c1", CheckType: "tcp", TimeoutMs: 1000}
	executeCheck(ctx, check, p, out)
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

func TestRunSessionRestartInMainLoop(t *testing.T) {
	srv := newFakeWSServer(t)

	go func() {
		srv.acceptAndJoin(t)
		stopDrain := make(chan struct{})
		go drainFrames(srv.conn, stopDrain)

		time.Sleep(50 * time.Millisecond)
		// Send restart event - exercised in the main loop select
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

func TestRunSessionSendsImmediateHeartbeat(t *testing.T) {
	origHostname := getHostname
	origContainer := runningInContainer
	defer func() {
		getHostname = origHostname
		runningInContainer = origContainer
	}()

	getHostname = func() (string, error) {
		return "tower-agent-01", nil
	}
	runningInContainer = func() bool { return true }

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)
	frame := agtWaitEvent(t, msgs, "heartbeat")
	var heartbeat pb.AgentHeartbeat
	agtDecodeBinary(t, frame.Payload, &heartbeat)

	if heartbeat.Version != version {
		t.Errorf("heartbeat version = %q, want %q", heartbeat.Version, version)
	}
	if heartbeat.Arch != runtime.GOARCH {
		t.Errorf("heartbeat arch = %q, want %q", heartbeat.Arch, runtime.GOARCH)
	}
	if heartbeat.Hostname != "tower-agent-01" {
		t.Errorf("heartbeat hostname = %q, want %q", heartbeat.Hostname, "tower-agent-01")
	}
	if net.ParseIP(heartbeat.IpAddress) == nil {
		t.Errorf("heartbeat ip_address = %q, want the session's local address", heartbeat.IpAddress)
	}
	if !heartbeat.Container {
		t.Error("heartbeat container = false, want the detected value")
	}
	if !heartbeat.SchedulesJobs {
		t.Error("heartbeat schedules_jobs = false with local scheduler enabled")
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
}

func TestRunSessionHeartbeats(t *testing.T) {
	origHB := heartbeatInterval
	origCHB := channelHeartbeatInterval
	origHostname := getHostname
	origContainer := runningInContainer
	defer func() {
		heartbeatInterval = origHB
		channelHeartbeatInterval = origCHB
		getHostname = origHostname
		runningInContainer = origContainer
	}()
	heartbeatInterval = 50 * time.Millisecond
	channelHeartbeatInterval = time.Hour
	// The server suppresses pushed self-updates for containerised agents, so
	// the heartbeat has to carry what the detector found.
	runningInContainer = func() bool { return true }

	var hostnameCalls atomic.Int32
	getHostname = func() (string, error) {
		hostnameCalls.Add(1)
		return "tower-agent-01", nil
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)
	for range 2 {
		frame := agtWaitEvent(t, msgs, "heartbeat")
		var heartbeat pb.AgentHeartbeat
		agtDecodeBinary(t, frame.Payload, &heartbeat)
		if heartbeat.Hostname != "tower-agent-01" {
			t.Fatalf("heartbeat hostname = %q, want %q", heartbeat.Hostname, "tower-agent-01")
		}
		if net.ParseIP(heartbeat.IpAddress) == nil {
			t.Fatalf("heartbeat ip_address = %q, want the session's local address", heartbeat.IpAddress)
		}
		if !heartbeat.Container {
			t.Fatal("heartbeat container = false, want the detected value")
		}
		if !heartbeat.SchedulesJobs {
			t.Fatal("heartbeat schedules_jobs = false with local scheduler enabled")
		}
	}
	if got := hostnameCalls.Load(); got != 1 {
		t.Fatalf("hostname resolved %d times, want once per session", got)
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
	}
}

func TestRunSessionHostnameErrorStillSendsHeartbeat(t *testing.T) {
	logs := agtCaptureLogs(t)
	origHB := heartbeatInterval
	origCHB := channelHeartbeatInterval
	origHostname := getHostname
	defer func() {
		heartbeatInterval = origHB
		channelHeartbeatInterval = origCHB
		getHostname = origHostname
	}()
	heartbeatInterval = 10 * time.Millisecond
	channelHeartbeatInterval = time.Hour
	getHostname = func() (string, error) {
		return "", errors.New("hostname unavailable")
	}

	ln := agtListen(t)
	done := make(chan error, 1)
	go func() { done <- runSession(context.Background(), agtURL(ln), "token", nil) }()

	conn, topic := agtAccept(t, ln)
	msgs := agtReadFrames(conn)
	frame := agtWaitEvent(t, msgs, "heartbeat")
	var heartbeat pb.AgentHeartbeat
	agtDecodeBinary(t, frame.Payload, &heartbeat)
	if heartbeat.Hostname != "" {
		t.Fatalf("heartbeat hostname = %q after resolution error, want empty", heartbeat.Hostname)
	}
	if !logs.has("resolve hostname error=hostname unavailable") {
		t.Fatalf("hostname resolution error was not logged:\n%s", logs.dump())
	}

	agtSendEvent(t, conn, topic, "restart", json.RawMessage(`{}`))
	if err := <-done; !errors.Is(err, errRestartRequested) {
		t.Fatalf("runSession error = %v, want %v", err, errRestartRequested)
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

		// Close the connection from the server side - any writes by the
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
		Ref:     new("1"),
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
			Ref:     new("1"),
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
			Ref:     new("1"),
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
	snmpDial = func(context.Context, *pb.SnmpDevice) (snmpQuerier, func(), error) {
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
	snmpDial = func(context.Context, *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return nil, nil, fmt.Errorf("refused")
	}

	out := testQueue()
	dispatchJob(context.Background(), &pb.AgentJob{
		JobId:      "lldp-2",
		DeviceId:   "dev-2",
		JobType:    pb.JobType_LLDP_TOPOLOGY,
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.2"},
	}, testPools(t), out)

	if result := wantResult[*pb.LldpTopologyResult](t, out, "lldp_topology_result", 5*time.Second); result.JobId != "lldp-2" || result.DeviceId != "dev-2" {
		t.Fatalf("result = %+v, want job lldp-2 device dev-2", result)
	}
}

func TestSessionLoopRetriesResultWhenWriterQueueStalls(t *testing.T) {
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = 5 * time.Millisecond

	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := newResultQueue(1)
	result := outbound{event: "result", payload: json.RawMessage(`{"binary":"queued"}`)}
	if !results.enqueue(result) {
		t.Fatal("failed to seed result queue")
	}
	writeCh := make(chan writeRequest, 1)
	writeCh <- writeRequest{data: []byte("writer is stalled")}
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		results:    results,
	}

	err := s.loop(context.Background())
	if err == nil || !strings.Contains(err.Error(), "queue result result") {
		t.Fatalf("session loop error = %v, want result queue timeout", err)
	}
	retried, ok := results.takeRetry()
	if !ok || retried.event != result.event || len(results.items) != 0 || len(results.slots) != 1 {
		t.Fatal("failed write did not restore the result at the head with its reservation")
	}
}

func TestSessionLoopRetainsRetryWhenWriterQueueStalls(t *testing.T) {
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = 5 * time.Millisecond

	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := newResultQueue(1)
	result := outbound{event: "retried", payload: json.RawMessage(`{}`)}
	if !results.enqueue(result) {
		t.Fatal("failed to seed result queue")
	}
	results.retry(<-results.items)

	writeCh := make(chan writeRequest, 1)
	writeCh <- writeRequest{data: []byte("writer is stalled")}
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		results:    results,
	}

	err := s.loop(context.Background())
	if err == nil || !strings.Contains(err.Error(), "queue retried result") {
		t.Fatalf("session loop error = %v, want retried result queue timeout", err)
	}
	retried, ok := results.takeRetry()
	if !ok || retried.event != result.event {
		t.Fatal("failed retried write was not retained at the queue head")
	}
}

func TestSendResultMsgReportsWriterFailure(t *testing.T) {
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeCh := make(chan writeRequest)
	wantErr := errors.New("broken pipe")
	go func() {
		request := <-writeCh
		request.ack <- wantErr
	}()
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
	}

	err := s.sendResultMsg(outbound{event: "result", payload: json.RawMessage(`{}`)})
	if !errors.Is(err, wantErr) {
		t.Fatalf("sendResultMsg error = %v, want %v", err, wantErr)
	}
}

func TestSendResultMsgObservesSessionCancellation(t *testing.T) {
	t.Run("before writer accepts request", func(t *testing.T) {
		sessionCtx, cancel := context.WithCancel(context.Background())
		cancel()
		s := &session{
			ctx:        sessionCtx,
			cancel:     cancel,
			writeCh:    make(chan writeRequest),
			errCh:      make(chan error, 1),
			writeErrCh: make(chan error, 1),
		}

		if err := s.sendResultMsg(outbound{event: "result", payload: json.RawMessage(`{}`)}); !errors.Is(err, errSessionCancelled) {
			t.Fatalf("sendResultMsg error = %v, want %v", err, errSessionCancelled)
		}
	})

	t.Run("while writer owns request", func(t *testing.T) {
		sessionCtx, cancel := context.WithCancel(context.Background())
		writeCh := make(chan writeRequest)
		go func() {
			<-writeCh
			cancel()
		}()
		s := &session{
			ctx:        sessionCtx,
			cancel:     cancel,
			writeCh:    writeCh,
			errCh:      make(chan error, 1),
			writeErrCh: make(chan error, 1),
		}

		if err := s.sendResultMsg(outbound{event: "result", payload: json.RawMessage(`{}`)}); !errors.Is(err, errSessionCancelled) {
			t.Fatalf("sendResultMsg error = %v, want %v", err, errSessionCancelled)
		}
	})
}

func TestCompletedResultWriteDrainsAcknowledgment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ack := make(chan error, 1)
		ack <- nil
		if ok, err := completedResultWrite("result", ack); !ok || err != nil {
			t.Fatalf("completedResultWrite = (%t, %v), want (true, nil)", ok, err)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		wantErr := errors.New("broken pipe")
		ack := make(chan error, 1)
		ack <- wantErr
		ok, err := completedResultWrite("result", ack)
		if !ok || !errors.Is(err, wantErr) {
			t.Fatalf("completedResultWrite = (%t, %v), want true with wrapped error", ok, err)
		}
	})

	t.Run("pending", func(t *testing.T) {
		if ok, err := completedResultWrite("result", make(chan error)); ok || err != nil {
			t.Fatalf("completedResultWrite = (%t, %v), want (false, nil)", ok, err)
		}
	})
}

func TestResultWriteAfterCancellationPrefersAcknowledgment(t *testing.T) {
	s := &session{
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
	}

	ack := make(chan error, 1)
	ack <- nil
	if err := s.resultWriteAfterCancellation("result", ack); err != nil {
		t.Fatalf("completed write lost to cancellation: %v", err)
	}

	readErr := errors.New("connection reset")
	s.errCh <- readErr
	if err := s.resultWriteAfterCancellation("result", make(chan error)); !errors.Is(err, readErr) {
		t.Fatalf("pending write cancellation error = %v, want %v", err, readErr)
	}
}

func TestSessionLoopSendsRetriedResultBeforeNewerResult(t *testing.T) {
	results := newResultQueue(2)
	if !results.enqueue(outbound{event: "older", payload: json.RawMessage(`{}`)}) {
		t.Fatal("failed to queue older result")
	}
	older := <-results.items
	if !results.enqueue(outbound{event: "newer", payload: json.RawMessage(`{}`)}) {
		t.Fatal("failed to queue newer result")
	}
	results.retry(older)

	agentCtx, stopAgent := context.WithCancel(context.Background())
	sessionCtx, stopSession := context.WithCancel(context.Background())
	defer stopSession()
	writeCh := make(chan writeRequest)
	s := &session{
		ctx:        sessionCtx,
		cancel:     stopSession,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		results:    results,
	}
	done := make(chan error, 1)
	go func() { done <- s.loop(agentCtx) }()

	for _, want := range []string{"older", "newer"} {
		request := <-writeCh
		var msg channelMsg
		if err := json.Unmarshal(request.data, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Event != want {
			t.Fatalf("result event = %q, want %q", msg.Event, want)
		}
		request.ack <- nil
	}

	stopAgent()
	if err := <-done; err != nil {
		t.Fatalf("session loop returned %v after agent shutdown", err)
	}
}

func TestSessionLoopSendsOverloadNoticeOutsideResultSpool(t *testing.T) {
	notices := make(chan outbound, 1)
	notices <- outbound{event: "error", payload: json.RawMessage(`{}`)}

	agentCtx, stopAgent := context.WithCancel(context.Background())
	sessionCtx, stopSession := context.WithCancel(context.Background())
	defer stopSession()
	writeCh := make(chan writeRequest)
	s := &session{
		ctx:        sessionCtx,
		cancel:     stopSession,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		results:    newResultQueue(1),
		notices:    notices,
	}
	done := make(chan error, 1)
	go func() { done <- s.loop(agentCtx) }()

	request := <-writeCh
	var msg channelMsg
	if err := json.Unmarshal(request.data, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Event != "error" {
		t.Fatalf("notice event = %q, want error", msg.Event)
	}
	request.ack <- nil

	stopAgent()
	if err := <-done; err != nil {
		t.Fatalf("session loop returned %v after agent shutdown", err)
	}
}

func TestSessionLoopReportsOverloadNoticeWriteFailure(t *testing.T) {
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = 5 * time.Millisecond

	notices := make(chan outbound, 1)
	notices <- outbound{event: "error", payload: json.RawMessage(`{}`)}
	writeCh := make(chan writeRequest, 1)
	writeCh <- writeRequest{data: []byte("writer is stalled")}
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		writeCh:    writeCh,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		results:    newResultQueue(1),
		notices:    notices,
	}

	err := s.loop(context.Background())
	if err == nil || !strings.Contains(err.Error(), "queue error result") {
		t.Fatalf("session loop error = %v, want overload notice queue timeout", err)
	}
}

// ---------------------------------------------------------------------------
// write channel saturation
// ---------------------------------------------------------------------------

func TestEnqueueWriteFullQueueDoesNotCancelSession(t *testing.T) {
	logs := agtCaptureLogs(t)
	origTimeout := writeQueueTimeout
	defer func() { writeQueueTimeout = origTimeout }()
	writeQueueTimeout = 5 * time.Millisecond

	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	defer sessionCancel()
	writeCh := make(chan writeRequest, 1)
	queued := []byte("already queued")
	writeCh <- writeRequest{data: queued}

	if enqueueWrite(sessionCtx, writeCh, writeRequest{data: []byte("drop me")}, "result") {
		t.Fatal("enqueueWrite accepted a message after the full-queue timeout")
	}
	select {
	case <-sessionCtx.Done():
		t.Fatal("full write queue cancelled the session")
	default:
	}
	if got := <-writeCh; string(got.data) != string(queued) {
		t.Fatalf("queued message = %q, want original %q", got.data, queued)
	}
	if !logs.has("write channel full, dropping message event=result") {
		t.Fatalf("expected a write queue timeout log, got:\n%s", logs.dump())
	}
}

// agtStagedCtx drives enqueueWrite's two-stage select deterministically. The
// select statement evaluates ctx.Done() once per stage, so done(1) governs the
// non-blocking first attempt and done(2) the timed second attempt.
type agtStagedCtx struct {
	context.Context
	stage int
	done  func(stage int) <-chan struct{}
}

func (c *agtStagedCtx) Done() <-chan struct{} {
	c.stage++
	return c.done(c.stage)
}

func agtNeverDone() <-chan struct{} { return make(chan struct{}) }

func agtAlreadyDone() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func TestEnqueueWriteCancelledSessionRefusesImmediately(t *testing.T) {
	logs := agtCaptureLogs(t)
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = time.Minute

	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	sessionCancel()
	writeCh := make(chan writeRequest, 1)
	queued := []byte("already queued")
	writeCh <- writeRequest{data: queued}

	if enqueueWrite(sessionCtx, writeCh, writeRequest{data: []byte("too late")}, "result") {
		t.Fatal("enqueueWrite accepted a message on a cancelled session")
	}
	if got := <-writeCh; string(got.data) != string(queued) {
		t.Fatalf("queued message = %q, want original %q", got.data, queued)
	}
	if logs.has("write channel full, dropping message") {
		t.Fatalf("cancelled session logged a queue-full drop, got:\n%s", logs.dump())
	}
}

func TestEnqueueWriteAcceptedAfterQueueDrains(t *testing.T) {
	logs := agtCaptureLogs(t)
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = time.Minute

	writeCh := make(chan writeRequest, 1)
	writeCh <- writeRequest{data: []byte("already queued")}
	ctx := &agtStagedCtx{Context: context.Background()}
	ctx.done = func(stage int) <-chan struct{} {
		if stage == 2 {
			// The writer drains the queue between the two attempts.
			<-writeCh
		}
		return agtNeverDone()
	}

	data := []byte("accepted on retry")
	if !enqueueWrite(ctx, writeCh, writeRequest{data: data}, "result") {
		t.Fatal("enqueueWrite dropped a message the drained queue could accept")
	}
	if got := <-writeCh; string(got.data) != string(data) {
		t.Fatalf("queued message = %q, want %q", got.data, data)
	}
	if logs.has("write channel full, dropping message") {
		t.Fatalf("accepted message logged a queue-full drop, got:\n%s", logs.dump())
	}
}

func TestEnqueueWriteCancelledWhileWaitingForQueue(t *testing.T) {
	logs := agtCaptureLogs(t)
	origTimeout := writeQueueTimeout
	t.Cleanup(func() { writeQueueTimeout = origTimeout })
	writeQueueTimeout = time.Minute

	writeCh := make(chan writeRequest, 1)
	queued := []byte("already queued")
	writeCh <- writeRequest{data: queued}
	ctx := &agtStagedCtx{Context: context.Background()}
	ctx.done = func(stage int) <-chan struct{} {
		if stage == 1 {
			return agtNeverDone()
		}
		// The session is cancelled while the message waits for queue space.
		return agtAlreadyDone()
	}

	if enqueueWrite(ctx, writeCh, writeRequest{data: []byte("abandoned")}, "result") {
		t.Fatal("enqueueWrite accepted a message after the session was cancelled")
	}
	if got := <-writeCh; string(got.data) != string(queued) {
		t.Fatalf("queued message = %q, want original %q", got.data, queued)
	}
	if logs.has("write channel full, dropping message") {
		t.Fatalf("cancelled wait logged a queue-full drop, got:\n%s", logs.dump())
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
	conn    *net.TCPConn
	done    <-chan error
	cancel  context.CancelFunc
	release func()
}

// agtStallSession drives a live session into a fully stalled state:
//   - the writer goroutine is blocked mid-write on an oversized trap, because
//     the test server stops reading after the join,
//   - the session loop is parked while reporting that forwarded trap,
//   - msgCh (cap 100) is full, so the reader goroutine is blocked handing its
//     next message to the session loop instead of watching the socket.
func agtStallSession(t *testing.T, logs *agtLogSink, _ int) *agtStalledSession {
	t.Helper()

	s := &agtStalledSession{}
	hit, release := logs.gateOn("sent snmp trap")
	s.release = release

	ln := agtListen(t)
	traps := make(chan *pb.SnmpTrap, 1)
	traps <- agtTrap("10.0.0.1", 2<<20)

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	t.Cleanup(func() {
		cancel()
		release()
	})
	done := make(chan error, 1)
	go func() { done <- runSession(ctx, agtURL(ln), "token", traps) }()
	s.done = done

	conn, _ := agtAccept(t, ln)
	s.conn = conn
	_ = conn.SetReadBuffer(4096)
	select {
	case <-hit:
	case <-time.After(15 * time.Second):
		cancel()
		release()
		t.Fatalf("trap was never forwarded\nlogged:\n%s", logs.dump())
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
		release()
		t.Fatal("agent kept reading the socket; msgCh never filled")
	}
	return s
}

func TestAgtRunSessionReaderStopsWhileHandingOffMessage(t *testing.T) {
	logs := agtCaptureLogs(t)
	agtSilenceHeartbeats(t)

	s := agtStallSession(t, logs, 0)
	s.cancel()  // the reader is blocked on the hand-off: it must exit on cancel
	s.release() // let the session loop observe cancellation and return

	err := <-s.done
	if err != nil && strings.Contains(err.Error(), "read:") {
		t.Fatalf("runSession error = %v; the blocked reader should exit on session cancel, not report a read error", err)
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
	t.Parallel()

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

func TestPropAgtDecodeBinaryPayload(t *testing.T) {
	t.Parallel()

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
