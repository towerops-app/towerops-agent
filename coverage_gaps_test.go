package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// The tests in this file cover the thin error/branch paths that only trigger
// under timeouts, refusals and refusal-adjacent state the happy-path suite
// cannot reach.

func TestSessionFailDefault(t *testing.T) {
	ch := make(chan error, 1)
	ch <- errors.New("first")
	s := &session{cancel: func() {}}
	// Second failure must not block: the cause is already recorded.
	s.fail(ch, errors.New("second"))
	if got := <-ch; got.Error() != "first" {
		t.Fatalf("first error must win, got %v", got)
	}
}

func TestSessionStopPoolAndSchedulerTimeout(t *testing.T) {
	orig := poolShutdownTimeout
	poolShutdownTimeout = 30 * time.Millisecond
	t.Cleanup(func() { poolShutdownTimeout = orig })

	ctx, cancel := context.WithCancel(context.Background())
	pools := testPools(t)
	// Occupy one worker so its pool cannot drain inside the timeout.
	release := make(chan struct{})
	defer close(release)
	if !pools.snmp.submit(ctx, func() { <-release }) {
		t.Fatal("blocked task must be admitted")
	}
	// Park the scheduler on a job that never finishes so wait() times out.
	pools.scheduler.wg.Add(1)
	t.Cleanup(func() { pools.scheduler.wg.Add(-1) })

	ws, closeSrv := dialWS(t)
	defer closeSrv()
	s := &session{
		ctx:        context.Background(),
		cancel:     cancel,
		ws:         ws,
		ownsPools:  true,
		pools:      pools,
		scheduler:  pools.scheduler,
		writeCh:    make(chan writeRequest),
		writerDone: make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	close(s.writerDone)
	close(s.readerDone)
	start := time.Now()
	s.stop() // must return after the shared budget, not block on the worker
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("stop exceeded shutdown budget: %v", elapsed)
	}
}

func TestJoinWriteError(t *testing.T) {
	ws, closeSrv := dialWS(t)
	defer closeSrv()
	_ = ws.conn.CloseNow() // next write fails deterministically
	s := &session{
		ctx:   context.Background(),
		topic: "agent:cov",
		ws:    ws,
		v2:    true,
	}
	if err := s.join("token"); err == nil {
		t.Fatal("join must surface the write error")
	}
}

func TestJoinReplyCapabilities(t *testing.T) {
	ref := "1"
	s := &session{
		ctx:   context.Background(),
		topic: "agent:cov",
		msgCh: make(chan channelMsg, 1),
		errCh: make(chan error, 1),
		v2:    true,
	}
	payload, _ := json.Marshal(map[string]any{
		"status": "ok",
		"response": map[string]any{
			"capabilities": []string{capabilityResultBatch, capabilityInventoryUpdate},
		},
	})
	s.msgCh <- channelMsg{
		Topic:   "agent:cov",
		Event:   "phx_reply",
		Ref:     &ref,
		Payload: json.RawMessage(payload),
	}
	ws, closeSrv := dialWS(t)
	defer closeSrv()
	s.ws = ws
	if err := s.join("token"); err != nil {
		t.Fatalf("join: %v", err)
	}
	if !s.resultBatches || !s.inventoryUpdates {
		t.Error("capabilities must enable both raw lanes")
	}
}

func TestMarshalPhoenixEnvelopeV1(t *testing.T) {
	ref := "7"
	buf, data, binary, err := marshalPhoenixEnvelope(
		"agent:cov", "result", "j1", []byte(`{"a":1}`), &ref, false, false)
	if err != nil || data == nil || buf == nil {
		t.Fatalf("v1 envelope: %v", err)
	}
	if binary {
		t.Error("v1 envelope is never binary")
	}
	putFrameBuffer(buf)

	// The V2 dispatcher on a legacy session emits the same JSON frame.
	buf2, data2, bin2 := marshalChannelFrameV2("agent:cov", "result", "1", json.RawMessage(`{"a":1}`), &ref, false)
	if data2 == nil || bin2 {
		t.Error("v2 dispatcher must fall back to JSON on a legacy session")
	}
	putFrameBuffer(buf2)
}

func TestQueueResultFrameSessionError(t *testing.T) {
	orig := writeQueueTimeout
	writeQueueTimeout = 500 * time.Millisecond
	t.Cleanup(func() { writeQueueTimeout = orig })

	sessionCtx, cancel := context.WithCancel(context.Background())
	s := &session{
		ctx:     sessionCtx,
		writeCh: make(chan writeRequest), // unread: the write never completes
		results: newResultQueueForAgentBytes(sessionCtx, 1<<20),
	}
	// The session must pass the top ctx check, then die inside enqueueWrite's
	// timed wait: the Done arm beats the 500ms timer deterministically.
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if _, err := s.queueResultFrame(
		[]outbound{{event: "result", protoPayload: []byte("x")}}, "result", true); err == nil {
		t.Fatal("dead session must surface sessionErr")
	}
}

func TestInFlightResultsNil(t *testing.T) {
	if inFlightResults(nil) != nil {
		t.Fatal("nil write must return nil results")
	}
}

func TestLoopChannelHeartbeatEnqueueFailure(t *testing.T) {
	orig := writeQueueTimeout
	origHB := channelHeartbeatInterval
	writeQueueTimeout = 5 * time.Millisecond
	channelHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		writeQueueTimeout = orig
		channelHeartbeatInterval = origHB
	})

	ctx := context.Background()
	results := newResultQueueForAgentBytes(ctx, 1<<20)
	s, end := loopSession(ctx, results)
	defer end()
	s.writeCh = make(chan writeRequest) // unbuffered and unread: enqueue fails

	done := make(chan error, 1)
	go func() { done <- s.loop(context.Background()) }()
	// The heartbeat tick must fire and hit the putFrameBuffer else-arm;
	// give it a beat before cancelling.
	time.Sleep(50 * time.Millisecond)
	end()
	if err := <-done; err != nil && !errors.Is(err, errSessionCancelled) {
		t.Fatalf("loop: %v", err)
	}
}

func TestLoopBatchFlushWriteFailure(t *testing.T) {
	origDelay, origTimeout := resultBatchFlushDelay, writeQueueTimeout
	resultBatchFlushDelay = 5 * time.Millisecond
	writeQueueTimeout = 5 * time.Millisecond
	t.Cleanup(func() {
		resultBatchFlushDelay = origDelay
		writeQueueTimeout = origTimeout
	})

	ctx := context.Background()
	results := newResultQueueForAgentBytes(ctx, 1<<20)
	results.enqueue(outbound{event: "result", protoPayload: []byte("x"), lane: 2})
	s, end := loopSession(ctx, results)
	defer end()
	s.writeCh = make(chan writeRequest) // enqueueWrite times out
	s.resultBatches = true

	done := make(chan error, 1)
	go func() { done <- s.loop(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("batch flush write failure must end the loop")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loop did not end")
	}
}

func TestResultQueueForAgentBytesDefault(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 0)
	if q.byteLimit != defaultResultSpoolBytes {
		t.Errorf("default byte limit: %d", q.byteLimit)
	}
}

func TestResultQueueHoldGrow(t *testing.T) {
	// Guard arms first: count-mode and sequence-0 both return without holding.
	countQ := newResultQueue(4)
	countQ.hold(outbound{event: "result", sequence: 1, encodedBytes: 4})
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	q.hold(outbound{event: "result", sequence: 0, encodedBytes: 4})
	if q.sentCount != 0 {
		t.Fatal("guard arms must not hold")
	}
	// sent starts empty: the first hold grows it to 8 slots. Filling those
	// and holding one more forces the copy loop on the second grow.
	for seq := uint64(1); seq <= 9; seq++ {
		q.hold(outbound{event: "result", sequence: seq, encodedBytes: 4})
	}
	if q.sentCount != 9 || len(q.sent) < 9 {
		t.Fatalf("sentCount/len = %d/%d", q.sentCount, len(q.sent))
	}
}

func TestAckThroughPartial(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	for seq := uint64(1); seq <= 4; seq++ {
		q.hold(outbound{event: "result", sequence: seq, encodedBytes: 4})
	}
	// Guard arms: count-mode and cumulative=0 both return early.
	countQ := newResultQueue(4)
	if countQ.ackThrough(2) != 0 {
		t.Error("count-mode ackThrough must no-op")
	}
	if q.ackThrough(0) != 0 {
		t.Error("zero cumulative must no-op")
	}
	// Ack only the first two; seqs 3-4 stay held.
	if released := q.ackThrough(2); released != 2 {
		t.Fatalf("released = %d, want 2", released)
	}
	if q.sentCount != 2 {
		t.Fatalf("sentCount = %d, want 2", q.sentCount)
	}
}

func TestUnholdMiddle(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	for seq := uint64(1); seq <= 3; seq++ {
		q.hold(outbound{event: "result", sequence: seq, encodedBytes: 4})
	}
	// Guard arms.
	countQ := newResultQueue(4)
	countQ.unhold(2)
	q.unhold(0)
	q.unhold(2) // middle entry: tail compacts forward
	if q.sentCount != 2 {
		t.Fatalf("sentCount = %d", q.sentCount)
	}
	remaining := map[uint64]bool{}
	for i := range q.sentCount {
		remaining[q.sent[(q.sentHead+i)%len(q.sent)].sequence] = true
	}
	if !remaining[1] || !remaining[3] || remaining[2] {
		t.Errorf("remaining sequences: %v", remaining)
	}
}

func TestReleaseLockedReturnsBuffer(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	q.byteUsage.Store(8)
	q.depth.Store(1)
	q.releaseLocked(outbound{
		event:        "result",
		encodedBytes: 8,
		buf:          bytes.NewBuffer(nil),
	}, true)
	if q.byteUsage.Load() != 0 || q.depth.Load() != 0 {
		t.Errorf("release must zero accounting: %d %d", q.byteUsage.Load(), q.depth.Load())
	}
}

func TestReleaseCapacityCountAndReserved(t *testing.T) {
	// Count mode drains the slot channel.
	q := newResultQueue(4)
	q.slots <- struct{}{}
	q.releaseCapacity(outbound{event: "result"}, false)
	// Reserved lane drains reservedSlots instead.
	q2 := newResultQueue(4)
	q2.reservedSlots <- struct{}{}
	q2.releaseCapacity(outbound{event: "result", reservedSlot: true}, false)
	// Byte mode with a buffer returns it to the pool.
	q3 := newResultQueueForAgentBytes(context.Background(), 1<<20)
	q3.byteUsage.Store(4)
	q3.depth.Store(1)
	q3.releaseCapacity(outbound{event: "result", encodedBytes: 4, buf: bytes.NewBuffer(nil)}, true)
	if q3.byteUsage.Load() != 0 {
		t.Error("byte release must free the charge")
	}
}

func TestEnqueueIngressFull(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	// Fill the small ingress channel without a consumer: the next enqueue
	// releases the charge and reports a drop.
	for i := 0; i < resultIngressDepth; i++ {
		if !q.enqueue(outbound{event: "result", payload: json.RawMessage("x")}) {
			t.Fatalf("ingress slot %d must admit", i)
		}
	}
	if q.enqueue(outbound{event: "result", payload: json.RawMessage("x")}) {
		t.Fatal("full ingress must refuse")
	}
	if q.dropped.Load() == 0 {
		t.Error("refused enqueue must count a drop")
	}
}

func TestSubmitJobPingEngineRefusal(t *testing.T) {
	// Full engine submit queue → submitPingJob fails inside the ping pool
	// dispatch → reportPoolRejection + done.
	stopPingEngine()
	engine = newPingEngine(context.Background())
	engineOnce.Do(func() {})
	t.Cleanup(func() {
		engine.cancel()
		engine = nil
		engineOnce = sync.Once{}
	})
	for i := 0; i < cap(engine.submit); i++ {
		engine.submit <- &pingJob{ctx: context.Background(), cancel: func() {}}
	}
	defer func() {
		for len(engine.submit) > 0 {
			<-engine.submit
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)
	done := make(chan struct{}, 1)
	job := &pb.AgentJob{
		JobId:      "ping-refused",
		JobType:    pb.JobType_PING,
		DeviceId:   "dev-p",
		SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
	}
	ok := submitJob(ctx, job, pools, out, func() { done <- struct{}{} }, false)
	<-done
	if !ok {
		// submitJob still returns true for ping dispatch; the refusal is
		// reported asynchronously through notices.
		t.Error("ping dispatch must return true even when the engine refuses")
	}
	select {
	case notice := <-pools.notices:
		if notice.event != "error" {
			t.Errorf("notice event = %q", notice.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rejection notice missing")
	}
}

func TestSubmitJobClosedPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)
	pools.snmp.stop() // closed, not paused → reportPoolRejection
	done := make(chan struct{}, 1)
	job := &pb.AgentJob{
		JobId:      "snmp-refused",
		JobType:    pb.JobType_POLL,
		DeviceId:   "dev-s",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
	}
	if submitJob(ctx, job, pools, out, func() { done <- struct{}{} }, true) {
		t.Error("closed pool must refuse")
	}
	<-done
	select {
	case notice := <-pools.notices:
		if notice.event != "error" {
			t.Errorf("notice event = %q", notice.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rejection notice missing")
	}
}

func TestSubmitJobGateAcquireCancelled(t *testing.T) {
	// Covers the wait-path targets.acquire ctx-cancellation refusal.
	ctx, cancel := context.WithCancel(context.Background())
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)
	done := make(chan struct{}, 1)
	job := &pb.AgentJob{
		JobId:      "snmp-gate-cancelled",
		JobType:    pb.JobType_POLL,
		DeviceId:   "dev-g",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.2"},
	}

	// Hold the device gate so acquire blocks on the caller's context.
	releaseHeld := pools.targets.acquire(context.Background(), jobTargetKey(job))
	if releaseHeld == nil {
		t.Fatal("first acquire must succeed")
	}
	t.Cleanup(releaseHeld)

	// Cancel the job context mid-acquire with a delayed cancel so the gate
	// wait is in progress when it fires.
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	if submitJob(ctx, job, pools, out, func() { done <- struct{}{} }, true) {
		t.Error("cancelled gate acquire must refuse")
	}
	<-done
}

func TestRuntimeSettingDefaults(t *testing.T) {
	configureAgentRuntime(agentRuntimeConfig{
		ResultSpoolBytes:    4096,
		DisconnectGrace:     42 * time.Second,
		SNMPConcurrency:     12,
		MikrotikConcurrency: 7,
		PingConcurrency:     9,
		CheckConcurrency:    11,
	})
	t.Cleanup(func() {
		configureAgentRuntime(agentRuntimeConfig{
			SNMPDeviceRate:   50,
			ResultSpoolBytes: 64 << 20,
			DisconnectGrace:  15 * time.Minute,
		})
	})

	if got := resultSpoolByteLimit(); got != 4096 {
		t.Errorf("resultSpoolByteLimit = %d", got)
	}
	if got := disconnectGracePeriod(); got != 42*time.Second {
		t.Errorf("disconnectGracePeriod = %v", got)
	}
	if got := snmpPoolSize(); got != 12 {
		t.Errorf("snmpPoolSize = %d", got)
	}
	if got := mikrotikPoolSize(); got != 7 {
		t.Errorf("mikrotikPoolSize = %d", got)
	}
	if got := pingPoolSize(); got != 9 {
		t.Errorf("pingPoolSize = %d", got)
	}
	if got := checksPoolSize(); got != 11 {
		t.Errorf("checksPoolSize = %d", got)
	}
	if got := backupPoolSize(); got != 8 {
		t.Errorf("backupPoolSize = %d", got)
	}

	configureAgentRuntime(agentRuntimeConfig{})
	if got := resultSpoolByteLimit(); got != defaultResultSpoolBytes {
		t.Errorf("zero config must fall back: %d", got)
	}
	if got := disconnectGracePeriod(); got != 15*time.Minute {
		t.Errorf("zero grace must fall back: %v", got)
	}
}

func TestPollerGraceTimerDoesNotRestart(t *testing.T) {
	// Pin a long grace so the armed timer cannot fire while the test
	// inspects it; expiry is driven explicitly below.
	configureAgentRuntime(agentRuntimeConfig{
		DisconnectGrace: time.Hour,
	})
	t.Cleanup(func() {
		configureAgentRuntime(agentRuntimeConfig{
			SNMPDeviceRate:   50,
			ResultSpoolBytes: 64 << 20,
			DisconnectGrace:  15 * time.Minute,
		})
	})

	done := make(chan struct{})
	close(done)
	p := &processPoller{
		cancel:       func() {},
		maintainDone: done,
		stopDone:     make(chan struct{}),
	}
	p.attached.Store(true)
	p.disconnected()
	armed := p.graceTimer
	if armed == nil {
		t.Fatal("first disconnect must arm the grace countdown")
	}
	// The retry loop calls disconnected() after every failed attempt; the
	// countdown must keep the original deadline rather than restarting, or
	// the grace never expires while the agent keeps trying (issue 5150).
	p.disconnected()
	if p.graceTimer != armed {
		t.Fatal("second disconnect restarted the grace countdown")
	}
	// The countdown still runs the expiry path: advancing the armed timer
	// stops the poller.
	armed.Reset(time.Millisecond)
	select {
	case <-p.stopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("grace expiry did not stop the poller")
	}
}

func TestApplyInventoryUpdateEarlyReturns(t *testing.T) {
	ctx := context.Background()
	out := newResultQueueForAgent(ctx, 8)
	var nilPoller *processPoller
	// nil receiver
	nilPoller.applyInventoryUpdate(&pb.AgentInventoryUpdate{}, out)
	// nil update
	p := &processPoller{}
	p.applyInventoryUpdate(nil, out)
	// stopped poller
	p2 := &processPoller{pools: testPools(t)}
	p2.stopped.Store(true)
	p2.applyInventoryUpdate(&pb.AgentInventoryUpdate{}, out)
}

func TestInventoryDecoderCtxDone(t *testing.T) {
	deadCtx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &session{ctx: deadCtx}
	s.startInventoryDecoder()
	// Saturate the result channel so the decoder's send is unavailable and
	// the select must take the ctx.Done arm.
	for i := 0; i < inventoryDecodeQueueDepth; i++ {
		s.inventoryResult <- inventoryDecodeResult{event: "jobs"}
	}
	s.inventoryWork <- inventoryDecodeRequest{event: "jobs"}
	// Give the goroutine a chance; no deadlock is the assertion.
	time.Sleep(20 * time.Millisecond)
}

func TestInventoryResultAppliesViaPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)
	s := &session{
		jobCtx:    ctx,
		pools:     pools,
		scheduler: pools.scheduler,
		results:   out,
		poller:    &processPoller{pools: pools, scheduler: pools.scheduler},
	}
	s.applyInventoryDecode(inventoryDecodeResult{
		event:   "inventory_update",
		decoded: true,
		update:  &pb.AgentInventoryUpdate{Revision: 5},
	}, pools, out)

	// nil poller fallback applies directly.
	s.poller = nil
	s.applyInventoryDecode(inventoryDecodeResult{
		event:   "inventory_update",
		decoded: true,
		update:  &pb.AgentInventoryUpdate{Revision: 6},
	}, pools, out)
}

func TestApplyJobListRemoteScheduling(t *testing.T) {
	ctx := context.Background()
	pools := testPools(t)
	pools.localScheduling = false
	out := newResultQueueForAgent(ctx, 8)
	applyJobList(ctx, "jobs", &pb.AgentJobList{Jobs: []*pb.AgentJob{
		{JobId: "j1", JobType: pb.JobType_PING, SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"}},
	}}, pools, out)
	applyCheckList(ctx, "check_jobs", &pb.CheckList{Checks: []*pb.Check{
		{Id: "c1", CheckType: "tcp", IntervalSeconds: 60},
	}}, pools, out)
}

func TestApplyJobListStopAccepting(t *testing.T) {
	ctx := context.Background()
	pools := testPools(t)
	pools.stopAccepting.Store(true)
	out := newResultQueueForAgent(ctx, 8)
	applyJobList(ctx, "jobs", &pb.AgentJobList{}, pools, out)
	applyCheckList(ctx, "check_jobs", &pb.CheckList{}, pools, out)
}

func TestExpandInventoryQueryDedup(t *testing.T) {
	// Columns × indexes produce duplicates the appendOID dedup drops; the
	// empty OID and the zero index are skipped entirely.
	query := &pb.SnmpQuery{
		Oids:       []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.1.0", ""},
		OidColumns: []string{"", ".1.3.6.1.2.1.25"},
		OidIndexes: []uint32{0, 3, 3},
	}
	got := expandSnmpQueryOIDs(query)
	want := []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.25.3"}
	if len(got) != len(want) {
		t.Fatalf("expanded = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expanded[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFullSyncDefaultsAndRemoveChecks(t *testing.T) {
	ctx := context.Background()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)

	// ChunkCount/ChunkIndex unset must default to 1.
	update := &pb.AgentInventoryUpdate{Revision: 1, FullSync: true}
	applyInventoryUpdate(pools, pools.scheduler, update, out)
	if update.ChunkCount != 1 || update.ChunkIndex != 1 {
		t.Errorf("chunk defaults: %d %d", update.ChunkCount, update.ChunkIndex)
	}
}

func TestIncrementalRemoveChecks(t *testing.T) {
	ctx := context.Background()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)

	// Seed two checks via a full sync: removing one leaves the other, which
	// exercises the filtered append arm.
	full := &pb.AgentInventoryUpdate{
		Revision: 1,
		FullSync: true,
		UpsertChecks: []*pb.Check{
			{Id: "keep", CheckType: "tcp", IntervalSeconds: 60},
			{Id: "stays", CheckType: "tcp", IntervalSeconds: 60},
		},
	}
	applyInventoryUpdate(pools, pools.scheduler, full, out)

	inc := &pb.AgentInventoryUpdate{
		Revision:       2,
		RemoveCheckIds: []string{"keep"},
		Upserts:        []*pb.AgentJob{{JobId: "j9", JobType: pb.JobType_PING, SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"}}},
		RemoveJobIds:   []string{"ghost"},
	}
	applyInventoryUpdate(pools, pools.scheduler, inc, out)
	if pools.appliedRevision.Load() != 2 {
		t.Errorf("applied revision = %d", pools.appliedRevision.Load())
	}
}

func TestAssemblerBoundRejects(t *testing.T) {
	ctx := context.Background()
	pools := testPools(t)
	out := newResultQueueForAgent(ctx, 8)

	// First chunk near the bound; the second pushes over it.
	big := strings.Repeat("x", maxInventoryAssemblyBytes/2)
	update := &pb.AgentInventoryUpdate{
		Revision:   1,
		FullSync:   true,
		ChunkCount: 2,
		ChunkIndex: 1,
		Upserts:    []*pb.AgentJob{{JobId: big}},
	}
	applyInventoryUpdate(pools, pools.scheduler, update, out)

	second := &pb.AgentInventoryUpdate{
		Revision:   1,
		FullSync:   true,
		ChunkCount: 2,
		ChunkIndex: 2,
		Upserts:    []*pb.AgentJob{{JobId: big}},
	}
	applyInventoryUpdate(pools, pools.scheduler, second, out)
	select {
	case res := <-out.items:
		if res.event != "error" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("assembly bound rejection missing")
	}
}

func TestSchedulePhaseZeroInterval(t *testing.T) {
	if got := schedulePhase("job", 0); got != 0 {
		t.Errorf("schedulePhase(0) = %v", got)
	}
	if got := wallClockPhaseDelay("job", 0, time.Now()); got != 0 {
		t.Errorf("wallClockPhaseDelay(0) = %v", got)
	}
}

func TestSchedulerPhaseFallbackInterval(t *testing.T) {
	// A spec with no interval falls back to legacyJobInterval for phasing.
	ctx, cancel := context.WithCancel(context.Background())
	sched := newRecurringScheduler(ctx, realScheduleClock{})
	entry := &scheduleEntry{
		stopped: make(chan struct{}),
		spec: scheduleSpec{
			id:       "zero-interval",
			interval: 0,
			submit: func(ctx context.Context, done func()) bool {
				done()
				return true
			},
		},
	}
	sched.wg.Add(1)
	cancel() // run() computes the fallback phase then exits on ctx
	sched.run(ctx, entry)
	<-entry.stopped
}

func TestJobSummaryZeroTick(t *testing.T) {
	orig := jobSummaryInterval
	jobSummaryInterval = 10 * time.Millisecond
	t.Cleanup(func() { jobSummaryInterval = orig })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startJobSummaryLogger(ctx)
	defer stop()
	// No record* calls: ticks with zero counters hit the continue arm.
	time.Sleep(40 * time.Millisecond)
}

func TestNoteInventoryFootprintPerDeviceFloor(t *testing.T) {
	noteInventoryFootprint(4, 2) // 2/4 = 0 → floored to 1
	if got := inventoryAvgDeviceBytes.Load(); got != 1 {
		t.Errorf("per-device floor = %d", got)
	}
}

func TestDeliverNotifyFull(t *testing.T) {
	notify := make(chan pingSocketEvent, 1)
	notify <- pingSocketEvent{} // full: send takes default arm
	w := &pingWaiter{
		ch:     make(chan icmpReply, 1),
		notify: notify,
		dst:    net.ParseIP("10.0.0.1"),
	}
	s := &icmpSocket{}
	s.deliver(w, icmpReply{received: time.Now()})
	select {
	case <-w.ch:
	case <-time.After(time.Second):
		t.Fatal("waiter channel must still receive")
	}
}

func TestFallbackLoop(t *testing.T) {
	e, pj, out := newTestPingJob(t, true)
	done := make(chan struct{}, 1)
	pj.done = func() { done <- struct{}{} }
	orig := execPing
	t.Cleanup(func() { execPing = orig })
	execPing = func(ctx context.Context, ip string, timeoutMs int) (float64, error) {
		return 2.0, nil
	}
	var wg sync.WaitGroup
	e.wg.Add(1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.runFallback()
	}()
	e.fallback <- pj
	select {
	case <-out.items:
	case <-time.After(2 * time.Second):
		t.Fatal("fallback round produced no result")
	}
	e.cancel()
	wg.Wait()
}

func TestSNMPDeviceStateDialRetries(t *testing.T) {
	state := newSNMPDeviceState(1000)
	job := &pb.AgentJob{
		JobId:          "dial-retries",
		SnmpDevice:     &pb.SnmpDevice{Ip: "127.0.0.1", Community: "public", Version: "2c"},
		SnmpRetries:    0,
		SnmpRetriesSet: true,
	}
	conn, release, err := state.dial(context.Background(), job)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer release()
	limited, ok := conn.(*rateLimitedQuerier)
	if !ok {
		t.Fatalf("conn = %T", conn)
	}
	inner, ok := limited.q.(*gosnmp.GoSNMP)
	if !ok {
		t.Fatalf("inner = %T", limited.q)
	}
	if inner.Retries != 0 {
		t.Errorf("SnmpRetriesSet with 0 must pin retries to 0: %d", inner.Retries)
	}
}

func TestSNMPDialNoRetriesCtx(t *testing.T) {
	state := newSNMPDeviceState(1000)
	job := &pb.AgentJob{
		JobId:      "dial-noretry",
		SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1", Community: "public", Version: "2c"},
	}
	ctx := snmpWithoutRetries(context.Background())
	conn, release, err := state.dial(ctx, job)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer release()
	limited := conn.(*rateLimitedQuerier)
	inner := limited.q.(*gosnmp.GoSNMP)
	if inner.Retries != 0 || inner.Timeout != snmpSilentProbeTimeout {
		t.Errorf("silent probe ctx: retries=%d timeout=%v", inner.Retries, inner.Timeout)
	}
}

func TestSNMPDialReleaseAfterCancel(t *testing.T) {
	// release() after ctx cancellation must close the socket and evict the
	// cached session — the arm previously covered only by poll timing.
	state := newSNMPDeviceState(1000)
	job := &pb.AgentJob{
		JobId:      "dial-release-cancel",
		SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1", Community: "public", Version: "2c"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, release, err := state.dial(ctx, job)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sock := conn.(*rateLimitedQuerier).q.(*gosnmp.GoSNMP).Conn
	cancel()
	release()
	if state.session != nil {
		t.Error("cancelled release must evict the cached session")
	}
	if _, err := sock.Write([]byte("x")); err == nil {
		t.Error("cancelled release must close the socket")
	}
}

func TestObserveRTTBranches(t *testing.T) {
	s := newSNMPDeviceState(10)
	s.observeRTT(0) // non-positive ignored
	if s.rtt != 0 {
		t.Error("zero sample must not set rtt")
	}
	s.observeRTT(5 * time.Millisecond)
	if s.rtt != 5*time.Millisecond {
		t.Errorf("first sample sets rtt: %v", s.rtt)
	}
	s.observeRTT(10 * time.Millisecond)
	if s.rtt == 0 {
		t.Error("second sample must still leave rtt set")
	}
}

func TestWalkTooBigNilState(t *testing.T) {
	ctx := context.Background()
	state := newSNMPDeviceState(10)
	// tooBig with nil queue state halves repetitions (>1) then retries.
	calls := 0
	bulk := &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		calls++
		if calls == 1 {
			return &gosnmp.SnmpPacket{Error: gosnmp.TooBig}, nil
		}
		return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.9", Type: gosnmp.EndOfMibView},
		}}, nil
	}}
	_, errs := snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, nil)
	_ = state
	if calls < 2 {
		t.Errorf("halved retry must re-request: %d calls", calls)
	}
	_ = errs
}

func TestWalkFullResponseNilState(t *testing.T) {
	ctx := context.Background()
	// A full first response (vars == active*repetitions) with nil state
	// adapts repetitions upward: covered by a second call carrying a small
	// varbind count that ends the walk.
	calls := 0
	bulk := &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		calls++
		if calls == 1 {
			vars := make([]gosnmp.SnmpPDU, snmpMaxRepetitions)
			for i := range vars {
				vars[i] = gosnmp.SnmpPDU{
					Name:  ".1.3.6.1." + string(rune('a'+i%26)),
					Type:  gosnmp.Integer,
					Value: i,
				}
			}
			return &gosnmp.SnmpPacket{Variables: vars}, nil
		}
		return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.zzz", Type: gosnmp.EndOfMibView},
		}}, nil
	}}
	_, _ = snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, nil)
	if calls < 2 {
		t.Errorf("full response should trigger another round: %d", calls)
	}
}

func TestWalkAbsorbError(t *testing.T) {
	ctx := context.Background()
	// Second binding for the same root is non-increasing → pduErr path.
	bulk := &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.5", Type: gosnmp.Integer, Value: 1},
			{Name: ".1.3.6.1.2", Type: gosnmp.Integer, Value: 2}, // decreases
		}}, nil
	}}
	_, errs := snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, nil)
	if len(errs) == 0 || errs[0].err == nil {
		t.Error("non-increasing OID must error the root")
	}
}

func TestWalkExactRootStored(t *testing.T) {
	st := newSnmpWalkRootState(".1.3.6.1.2.1.1.1.0")
	done, exact, err := st.absorb(gosnmp.SnmpPDU{
		Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "leaf"})
	if err != nil || !done || !exact {
		t.Fatalf("exact leaf: done=%v exact=%v err=%v", done, exact, err)
	}
}

func TestWalkDoneRootSkipsPDU(t *testing.T) {
	ctx := context.Background()
	// Two roots: root A ends on the first binding, root B's later binding for
	// the done root is skipped via st.done continue.
	calls := 0
	bulk := &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		calls++
		vars := []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.4.1.9", Type: gosnmp.EndOfMibView}, // root A done
			{Name: ".1.3.6.1.4.1.10.1", Type: gosnmp.Integer, Value: 1},
		}
		if calls > 1 {
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.4.1.10.9", Type: gosnmp.EndOfMibView},
			}}, nil
		}
		return &gosnmp.SnmpPacket{Variables: vars}, nil
	}}
	_, _ = snmpWalkRoots(ctx, bulk,
		[]string{".1.3.6.1.4.1.9", ".1.3.6.1.4.1.10"}, false, nil)
}

func TestExecuteSnmpJobPlainConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-plain",
		DeviceId:   "cov-plain-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.8", Community: "public", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_WALK,
			Oids:      []string{".1.3.6.1"},
		}},
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.9", Type: gosnmp.EndOfMibView},
			}}, nil
		}}, func() {}, nil
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
}

func TestExecuteSnmpJobWalkTimeoutMarksSilent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-walktimeout",
		DeviceId:   "cov-walktimeout-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.9", Community: "public", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_WALK,
			Oids:      []string{".1.3.6.1"},
		}},
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
			return nil, errTimeoutForTest{}
		}}, func() {}, nil
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
	state := defaultSNMPEngine.state(job)
	if !state.isSilent() {
		t.Error("unanswered walk must mark the device silent")
	}
}

type errTimeoutForTest struct{}

func (errTimeoutForTest) Error() string   { return "request timeout (after 0 retries)" }
func (errTimeoutForTest) Timeout() bool   { return true }
func (errTimeoutForTest) Temporary() bool { return true }

type fakeNetConn struct {
	net.Conn // nil embedded; only LocalAddr is exercised
}

func (fakeNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5050}
}

func TestRecordAndDrainLocalAddr(t *testing.T) {
	ch := make(chan string, 1)
	recordLocalAddr(ch, fakeNetConn{})
	if got := lastLocalAddr(ch); got == "" {
		t.Error("recorded addr must drain")
	}
	// Second record on a full channel must not block.
	recordLocalAddr(ch, fakeNetConn{})
	recordLocalAddr(ch, fakeNetConn{})
	if got := lastLocalAddr(ch); got == "" {
		t.Error("drained channel must yield the last recorded addr")
	}
	if got := lastLocalAddr(ch); got != "" {
		t.Errorf("empty channel must yield \"\": %q", got)
	}
}

func TestShellCloseDeadlinePath(t *testing.T) {
	// stdin that never drains: close abandons the write after
	// shellWriteDeadline then unblocks when the channel closes.
	fake := startFakeShellServer(t, "", "sw1> ", shellScript{})
	defer fake.cleanup()
	sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
	block := make(chan struct{})
	sess.stdin = &cbBlockWriter{release: block}
	done := make(chan struct{})
	go func() {
		sess.close()
		close(done)
	}()
	time.Sleep(1100 * time.Millisecond) // let the deadline arm fire
	close(block)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close hung past shellWriteDeadline")
	}
}

type cbBlockWriter struct {
	release chan struct{}
	err     error
}

func (w *cbBlockWriter) Write(p []byte) (int, error) {
	if w.release != nil {
		<-w.release
		w.release = nil
	}
	return len(p), w.err
}

func (w *cbBlockWriter) Close() error { return nil }

func TestExecuteSnmpJobLimitedGetTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-limited-timeout",
		DeviceId:   "cov-limited-timeout-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.11", Community: "public", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_GET,
			Oids:      []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0"},
		}},
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(dialCtx context.Context, j *pb.AgentJob) (snmpQuerier, func(), error) {
		return &rateLimitedQuerier{
			ctx:    dialCtx,
			cached: true,
			device: newTokenBucket(1000, nil),
			q: &mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return nil, errTimeoutForTest{}
			}},
		}, func() {}, nil
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
}
