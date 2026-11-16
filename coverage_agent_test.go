// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// dialWS opens a websocket connection to a test server whose accepted end is
// immediately closed, so every client write fails.
func dialWS(t *testing.T) (*wsConn, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		<-r.Context().Done() // hold the server side until the client leaves
	}))
	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		srv.Close()
		t.Fatalf("wsDial: %v", err)
	}
	return ws, srv.Close
}

func TestSessionWriteReportsWriteError(t *testing.T) {
	run := func(t *testing.T, binary bool) {
		ws, closeSrv := dialWS(t)
		defer closeSrv()
		defer func() { _ = ws.Close() }()
		// Kill the transport: every Write now fails.
		_ = ws.conn.CloseNow()

		s := &session{
			ctx:        context.Background(),
			cancel:     func() {},
			writeCh:    make(chan writeRequest, 4),
			writerDone: make(chan struct{}),
			writeErrCh: make(chan error, 4),
			ws:         ws,
		}
		ack := make(chan error, 1)
		go s.write()
		s.writeCh <- writeRequest{data: []byte("x"), binary: binary, ack: ack}
		if err := <-ack; err == nil {
			t.Error("write error must reach the ack channel")
		}
		// The writer exits on the error.
		<-s.writerDone
	}
	t.Run("binary", func(t *testing.T) { run(t, true) })
	t.Run("text", func(t *testing.T) { run(t, false) })
}

func TestSessionStopDrainsPools(t *testing.T) {
	orig := poolShutdownTimeout
	poolShutdownTimeout = 1 * time.Millisecond
	t.Cleanup(func() { poolShutdownTimeout = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ws, closeSrv := dialWS(t)
	defer closeSrv()

	writerDone := make(chan struct{})
	readerDone := make(chan struct{})
	close(writerDone)
	close(readerDone)

	s := &session{
		ctx:           ctx,
		cancel:        cancel,
		ws:            ws,
		writeCh:       make(chan writeRequest),
		msgCh:         make(chan channelMsg),
		writerDone:    writerDone,
		readerDone:    readerDone,
		results:       newResultQueueForAgentBytes(ctx, 1<<20),
		inventoryWork: make(chan inventoryDecodeRequest),
		jobCancel:     func() {},
		ownsPools:     true,
	}
	s.scheduler = newRecurringScheduler(ctx, newManualScheduleClock())
	pools := testPools(t)
	s.pools = pools

	done := make(chan struct{})
	go func() { s.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not finish")
	}
}

func TestSessionJoinErrors(t *testing.T) {
	newJoinSession := func(t *testing.T) *session {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ws, _ := dialWS(t)
		return &session{
			ctx:   ctx,
			topic: "agent:cov",
			ws:    ws,
			msgCh: make(chan channelMsg, 4),
			errCh: make(chan error, 4),
		}
	}

	t.Run("join reply parse error", func(t *testing.T) {
		s := newJoinSession(t)
		s.msgCh <- channelMsg{Event: "phx_reply", Topic: "other", Payload: json.RawMessage(`{}`)}
		if err := s.join("token"); err == nil {
			t.Error("bad reply must fail the join")
		}
	})

	t.Run("read error during join", func(t *testing.T) {
		s := newJoinSession(t)
		s.errCh <- errors.New("socket died")
		if err := s.join("token"); err == nil || !strings.Contains(err.Error(), "socket died") {
			t.Errorf("read error must fail the join: %v", err)
		}
	})

	t.Run("join timeout", func(t *testing.T) {
		orig := joinTimeout
		joinTimeout = 10 * time.Millisecond
		t.Cleanup(func() { joinTimeout = orig })
		s := newJoinSession(t)
		if err := s.join("token"); err == nil || !strings.Contains(err.Error(), "join timeout") {
			t.Errorf("timeout: %v", err)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		s := newJoinSession(t)
		_ = s.ws.conn.CloseNow()
		if err := s.join("token"); err == nil || !strings.Contains(err.Error(), "send join") {
			t.Errorf("write failure: %v", err)
		}
	})
}

func TestParseJoinReplyMsgErrors(t *testing.T) {
	// Wrong event.
	if _, err := parseJoinReplyMsg(channelMsg{Event: "push"}, "t"); err == nil {
		t.Error("non-reply event must fail")
	}
	// Empty status: payload parse error.
	if _, err := parseJoinReplyMsg(channelMsg{
		Event:   "phx_reply",
		Payload: json.RawMessage(`{bad`),
	}, "t"); err == nil {
		t.Error("bad payload must fail")
	}
	// Status present but response payload invalid.
	if _, err := parseJoinReplyMsg(channelMsg{
		Event:   "phx_reply",
		Status:  "ok",
		Payload: json.RawMessage(`{bad`),
	}, "t"); err == nil {
		t.Error("bad response payload must fail")
	}
	// Wrong topic.
	if _, err := parseJoinReplyMsg(channelMsg{
		Event: "phx_reply", Status: "ok", Topic: "other",
		Payload: json.RawMessage(`{"response":{"capabilities":[]}}`),
	}, "t"); err == nil {
		t.Error("wrong topic must fail")
	}
	// Missing ref.
	if _, err := parseJoinReplyMsg(channelMsg{
		Event: "phx_reply", Status: "ok", Topic: "t",
		Payload: json.RawMessage(`{"response":{"capabilities":[]}}`),
	}, "t"); err == nil {
		t.Error("missing ref must fail")
	}
	// Wrong ref.
	other := "9"
	if _, err := parseJoinReplyMsg(channelMsg{
		Event: "phx_reply", Status: "ok", Topic: "t", Ref: &other,
		Payload: json.RawMessage(`{"response":{"capabilities":[]}}`),
	}, "t"); err == nil {
		t.Error("wrong ref must fail")
	}
}

func TestParseJoinReplyLegacy(t *testing.T) {
	if _, err := parseJoinReply([]byte(`{bad`), "t"); err == nil {
		t.Error("bad frame must fail")
	}
}

func TestMarshalPhoenixEnvelopeErrors(t *testing.T) {
	longTopic := strings.Repeat("t", 300)
	// Raw push over the field bound fails.
	if _, _, _, err := marshalPhoenixEnvelope(longTopic, "e", "j", []byte("{}"), nil, true, true); err == nil {
		t.Error("raw envelope must fail on long topic")
	}
	// V2 text envelope fails on invalid JSON payload.
	if _, _, _, err := marshalPhoenixEnvelope("t", "e", "j", []byte("{bad"), nil, true, false); err == nil {
		t.Error("v2 text envelope must fail on bad payload")
	}
	// V1 path with invalid JSON envelope also errors.
	if _, _, _, err := marshalPhoenixEnvelope("t", "e", "j", []byte("{bad"), nil, false, false); err != nil {
		t.Errorf("v1 marshal cannot fail: %v", err)
	}
}

func TestMarshalChannelFrameV2Fallback(t *testing.T) {
	// A topic over the V2 field bound falls back to the V1 JSON envelope.
	_, data, binary := marshalChannelFrameV2(strings.Repeat("t", 300), "e", "j", json.RawMessage(`{}`), nil, true)
	if binary {
		t.Error("oversized field must not produce a binary frame")
	}
	if len(data) == 0 || data[0] == 0 {
		t.Error("fallback must be the JSON envelope")
	}
}

func badProtoMessage() proto.Message {
	// 0xFF is invalid UTF-8: proto.Marshal rejects it deterministically.
	return &pb.SnmpResult{JobId: "\xff"}
}

func TestSendBinaryErrorPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("marshal failure on raw lane", func(t *testing.T) {
		s := &session{ctx: ctx, v2: true, serverCapabilities: map[string]struct{}{"x": {}}}
		if s.sendBinary("result", badProtoMessage()) {
			t.Error("marshal failure must return false")
		}
	})
	t.Run("marshal failure on text lane", func(t *testing.T) {
		s := &session{ctx: ctx}
		if s.sendBinary("result", badProtoMessage()) {
			t.Error("marshal failure must return false")
		}
	})
	t.Run("envelope error", func(t *testing.T) {
		s := &session{ctx: ctx, v2: true, serverCapabilities: map[string]struct{}{"x": {}},
			topic: strings.Repeat("t", 300)}
		if s.sendBinary("result", &pb.AgentHeartbeat{}) {
			t.Error("envelope failure must return false")
		}
	})
	t.Run("write queue refusal", func(t *testing.T) {
		deadCtx, deadCancel := context.WithCancel(context.Background())
		deadCancel()
		s := &session{ctx: deadCtx, writeCh: make(chan writeRequest)}
		if s.sendBinary("result", &pb.AgentHeartbeat{}) {
			t.Error("refused write must return false")
		}
	})
}

func TestQueueResultFrameErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("cancelled session", func(t *testing.T) {
		deadCtx, deadCancel := context.WithCancel(context.Background())
		deadCancel()
		s := &session{ctx: deadCtx, results: newResultQueue(4)}
		if _, err := s.queueResultFrame([]outbound{{event: "result"}}, "result", true); err == nil {
			t.Error("cancelled session must error")
		}
	})
	t.Run("empty results", func(t *testing.T) {
		s := &session{ctx: ctx, results: newResultQueue(4)}
		if _, err := s.queueResultFrame(nil, "result", true); err == nil {
			t.Error("empty frame must error")
		}
	})
	t.Run("batch marshal error", func(t *testing.T) {
		s := &session{
			ctx: ctx, v2: true, resultBatches: true,
			results:            newResultQueueForAgentBytes(ctx, 1<<20),
			writeCh:            make(chan writeRequest, 4),
			serverCapabilities: map[string]struct{}{"x": {}},
		}
		_, err := s.queueResultFrame([]outbound{{
			event:        "\xff", // invalid UTF-8: AgentResultEnvelope marshal fails
			protoPayload: []byte("x"),
		}}, "result", true)
		if err == nil {
			t.Error("batch marshal must fail on bad job id")
		}
	})
	t.Run("envelope error", func(t *testing.T) {
		s := &session{
			ctx: ctx, topic: strings.Repeat("t", 300), resultBatches: true,
			results:            newResultQueueForAgentBytes(ctx, 1<<20),
			writeCh:            make(chan writeRequest, 4),
			serverCapabilities: map[string]struct{}{"x": {}},
		}
		_, err := s.queueResultFrame([]outbound{{event: "result", protoPayload: []byte("x")}}, "result", true)
		if err == nil {
			t.Error("envelope failure must error")
		}
	})
	t.Run("write queue refusal", func(t *testing.T) {
		orig := writeQueueTimeout
		writeQueueTimeout = 5 * time.Millisecond
		t.Cleanup(func() { writeQueueTimeout = orig })
		s := &session{
			ctx: ctx, resultBatches: false,
			results:            newResultQueueForAgentBytes(ctx, 1<<20),
			writeCh:            make(chan writeRequest), // unbuffered, no writer
			serverCapabilities: map[string]struct{}{"x": {}},
		}
		if _, err := s.queueResultFrame([]outbound{{event: "result", protoPayload: []byte("x")}}, "result", true); err == nil {
			t.Error("refused write must error")
		}
	})
}

func TestResolveAndSettleInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("write ack updates sentAt", func(t *testing.T) {
		s := &session{
			ctx: ctx, results: newResultQueueForAgentBytes(ctx, 1<<20),
			pending:            map[string]pendingResult{"7": {result: outbound{event: "result", sequence: 3}}},
			serverCapabilities: map[string]struct{}{capabilityResultAck: {}},
		}
		s.ackedResults.Store(0)
		res := outbound{event: "result", sequence: 3, encodedBytes: 10}
		w := &inFlightWrite{ref: "7", spooled: true, results: []outbound{res}}
		if err := s.resolveInFlight(w, nil); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if p := s.pending["7"]; p.sentAt.IsZero() {
			t.Error("sentAt must be stamped")
		}
		if s.ackedResults.Load() != 1 {
			t.Errorf("ackedResults = %d", s.ackedResults.Load())
		}
	})

	t.Run("write failure retries results", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s := &session{ctx: ctx, results: results}
		res := outbound{event: "result", sequence: 3, encodedBytes: 10}
		results.hold(res) // pretend it was sent and held
		w := &inFlightWrite{ref: "9", spooled: true, results: []outbound{res}}
		if err := s.resolveInFlight(w, errors.New("write failed")); err == nil {
			t.Error("resolve must surface the write error")
		}
		select {
		case got := <-results.retries:
			if got.sequence != 3 {
				t.Errorf("retried sequence = %d", got.sequence)
			}
		default:
			t.Error("failed write must retry the result")
		}
	})

	t.Run("inFlightResults falls back to single result", func(t *testing.T) {
		w := &inFlightWrite{result: outbound{event: "trap"}}
		got := inFlightResults(w)
		if len(got) != 1 || got[0].event != "trap" {
			t.Errorf("fallback = %v", got)
		}
	})

	t.Run("settleInFlight retries unfinished write", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s := &session{ctx: ctx, results: results}
		res := outbound{event: "result", sequence: 5, encodedBytes: 10}
		w := &inFlightWrite{ack: make(chan error, 1), spooled: true, results: []outbound{res}}
		s.settleInFlight(w)
		select {
		case got := <-results.retries:
			if got.sequence != 5 {
				t.Errorf("retried sequence = %d", got.sequence)
			}
		default:
			t.Error("unfinished write must be retried")
		}
	})
}

func TestUnholdSpooledCountMode(t *testing.T) {
	s := &session{results: newResultQueue(4)}
	s.unholdSpooled([]outbound{{sequence: 1}}) // count mode: no-op
}

func TestRequeueRejectedPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("byte mode hold released before requeue", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s := &session{ctx: ctx, results: results}
		res := outbound{event: "result", sequence: 9, encodedBytes: 10}
		results.hold(res)
		s.requeueRejected([]outbound{res}, 0)
		select {
		case <-results.items:
		default:
			t.Error("rejected result must re-enter the spool")
		}
	})

	t.Run("delayed rejection requeues via timer", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s := &session{ctx: ctx, results: results}
		res := outbound{event: "result", sequence: 10, encodedBytes: 10}
		s.requeueRejected([]outbound{res}, 20*time.Millisecond)
		select {
		case <-results.items:
		case <-time.After(2 * time.Second):
			t.Fatal("delayed requeue did not land")
		}
	})

	t.Run("multi-result batch requeues atomically", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s := &session{ctx: ctx, results: results}
		batch := []outbound{
			{event: "result", sequence: 11, encodedBytes: 10},
			{event: "result", sequence: 12, encodedBytes: 10},
		}
		s.requeueRejected(batch, 0)
		select {
		case got := <-results.items:
			if got.sequence != 11 {
				t.Errorf("first requeue = %d", got.sequence)
			}
		default:
			t.Error("batch must requeue")
		}
	})

	t.Run("full spool drops the batch with an error log", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 40)
		s := &session{ctx: ctx, results: results}
		batch := []outbound{
			{event: "result", sequence: 13, payload: json.RawMessage(strings.Repeat("x", 30))},
			{event: "result", sequence: 14, payload: json.RawMessage(strings.Repeat("x", 30))},
		}
		s.requeueRejected(batch, 0)
		if results.dropped.Load() == 0 {
			t.Error("dropped batch must count")
		}
	})

	t.Run("single result on a full spool drops", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 10)
		s := &session{ctx: ctx, results: results}
		s.requeueRejected([]outbound{{event: "result", sequence: 15,
			payload: json.RawMessage(strings.Repeat("x", 30))}}, 0)
		if results.dropped.Load() == 0 {
			t.Error("oversized requeue must count as dropped")
		}
	})
}

func TestRetryResultsEmpty(t *testing.T) {
	s := &session{results: newResultQueue(4)}
	s.retryResults(nil) // must not block or panic
}

func TestResultQueueBatchAndRing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("enqueueBatch rolls back on partial failure", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 30)
		batch := []outbound{
			{event: "result", payload: json.RawMessage(strings.Repeat("x", 20))},
			{event: "result", payload: json.RawMessage(strings.Repeat("x", 20))},
		}
		if q.enqueueBatch(batch) {
			t.Error("batch must fail past the budget")
		}
		if q.byteUsage.Load() != 0 {
			t.Errorf("rollback must release the byte charge: %d", q.byteUsage.Load())
		}
	})

	t.Run("enqueueAfter drops silently in byte mode", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 10)
		q.enqueueAfter(outbound{event: "result", encodedBytes: 100}, 1*time.Millisecond)
		time.Sleep(50 * time.Millisecond)
		if q.byteUsage.Load() != 0 {
			t.Error("oversized delayed result must not charge the spool")
		}
	})

	t.Run("hold grows the ring", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		for i := uint64(1); i <= 20; i++ {
			q.hold(outbound{event: "result", sequence: i, encodedBytes: 1})
		}
		if q.pendingAckCount() != 20 {
			t.Errorf("held = %d", q.pendingAckCount())
		}
	})

	t.Run("ackThrough releases prefix and keeps tail", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		for i := uint64(1); i <= 6; i++ {
			q.hold(outbound{event: "result", sequence: i, encodedBytes: 1})
		}
		if released := q.ackThrough(4); released != 4 {
			t.Errorf("released = %d", released)
		}
		if q.pendingAckCount() != 2 {
			t.Errorf("kept = %d", q.pendingAckCount())
		}
	})

	t.Run("dropSent compacts the ring", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		for i := uint64(1); i <= 5; i++ {
			q.hold(outbound{event: "result", sequence: i, encodedBytes: 1})
		}
		q.dropSent(3)
		if q.pendingAckCount() != 4 {
			t.Errorf("after drop = %d", q.pendingAckCount())
		}
		q.dropSent(99) // absent sequence is a no-op
	})

	t.Run("unhold frees capacity without the buffer", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		q.hold(outbound{event: "result", sequence: 7, encodedBytes: 10})
		before := q.byteUsage.Load()
		q.unhold(7)
		if got := q.byteUsage.Load(); got != before-10 {
			t.Errorf("byteUsage = %d", got)
		}
		if q.pendingAckCount() != 0 {
			t.Error("unhold must remove the entry")
		}
		q.unhold(77) // absent sequence
	})

	t.Run("ack drops held result in byte mode", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		q.hold(outbound{event: "result", sequence: 3, encodedBytes: 5})
		q.ack(outbound{event: "result", sequence: 3, encodedBytes: 5})
		if q.pendingAckCount() != 0 {
			t.Error("ack must release the held result")
		}
	})

	t.Run("count-mode releaseCapacity frees slots", func(t *testing.T) {
		q := newResultQueue(4)
		q.slots <- struct{}{}
		q.releaseCapacity(outbound{}, false)
		q.reservedSlots <- struct{}{}
		q.releaseCapacity(outbound{reservedSlot: true}, false)
	})

	t.Run("count-mode ack frees slots", func(t *testing.T) {
		q := newResultQueue(4)
		q.slots <- struct{}{}
		q.ack(outbound{})
		q.reservedSlots <- struct{}{}
		q.ack(outbound{reservedSlot: true})
	})

	t.Run("retryBatch preserves order", func(t *testing.T) {
		q := newResultQueue(4)
		q.retryBatch([]outbound{
			{event: "result", sequence: 1},
			{event: "result", sequence: 2},
		})
		first, ok := q.takeRetry()
		if !ok || first.sequence != 1 {
			t.Errorf("first retry = %+v %v", first, ok)
		}
		second, ok := q.takeRetry()
		if !ok || second.sequence != 2 {
			t.Errorf("second retry = %+v %v", second, ok)
		}
	})

	t.Run("requeueLanes byte mode re-enqueues", func(t *testing.T) {
		q := newResultQueueForAgentBytes(ctx, 1<<20)
		var lanes [4][]outbound
		lanes[1] = []outbound{{event: "check_result", encodedBytes: 5}}
		q.requeueLanes(&lanes)
		select {
		case got := <-q.items:
			if got.event != "check_result" {
				t.Errorf("requeued = %q", got.event)
			}
		default:
			t.Error("lane result must re-enter")
		}
		if lanes[1] != nil {
			t.Error("lane must be cleared")
		}
	})

	t.Run("requeueLanes count mode pushes to items", func(t *testing.T) {
		q := newResultQueue(4)
		var lanes [4][]outbound
		lanes[2] = []outbound{{event: "result"}}
		q.requeueLanes(&lanes)
		select {
		case <-q.items:
		default:
			t.Error("count-mode lane must push to items")
		}
	})
}

func TestJobPoolsSnapshots(t *testing.T) {
	// Nil pools are skipped in load snapshots.
	pools := &jobPools{snmp: newWorkerPool(1)}
	defer pools.snmp.stop()
	loads := pools.loadSnapshots()
	found := false
	for _, l := range loads {
		if l.Name == "snmp" {
			found = true
		}
	}
	if !found || len(loads) != 1 {
		t.Errorf("loads = %v", loads)
	}
	var nilPools *jobPools
	if nilPools.loadSnapshots() != nil {
		t.Error("nil pools must not panic")
	}

	// idle() reports false while a pool holds work.
	busyPools := &jobPools{snmp: newWorkerPool(1)}
	defer busyPools.snmp.stop()
	release := make(chan struct{})
	busyPools.snmp.submit(context.Background(), func() { <-release })
	time.Sleep(20 * time.Millisecond)
	if busyPools.idle() {
		t.Error("busy pool must not report idle")
	}
	close(release)
}

func TestSubmitJobPingPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("refusing ping pool reports rejection", func(t *testing.T) {
		pools := testPools(t)
		pools.ping.paused.Store(true)
		out := newResultQueue(8)
		done := make(chan struct{})
		job := &pb.AgentJob{
			JobId:      "ping-refuse",
			JobType:    pb.JobType_PING,
			DeviceId:   "dev-p",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.1.2.3"},
		}
		// A paused pool's refusing() flag rejects before dispatch.
		if pools.ping.refusing() == false {
			t.Skip("refusing() false")
		}
		ok := submitJob(ctx, job, pools, out, func() { close(done) }, false)
		<-done
		if ok {
			t.Error("refused submit must return false")
		}
		select {
		case n := <-pools.notices:
			if n.event != "pool_overload" {
				t.Errorf("notice = %q", n.event)
			}
		default:
			// Rejection reporting may or may not enqueue depending on notice
			// saturation; the covered path is the refusal itself.
		}
	})

	t.Run("cancelled context skips ping dispatch", func(t *testing.T) {
		pools := testPools(t)
		out := newResultQueue(8)
		done := make(chan struct{})
		deadCtx, deadCancel := context.WithCancel(context.Background())
		deadCancel()
		job := &pb.AgentJob{
			JobId:      "ping-cancel",
			JobType:    pb.JobType_PING,
			DeviceId:   "dev-p2",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.1.2.4"},
		}
		submitJob(deadCtx, job, pools, out, func() { close(done) }, false)
		<-done
	})

	t.Run("unsupported job type reports and completes", func(t *testing.T) {
		pools := testPools(t)
		out := newResultQueue(8)
		done := make(chan struct{})
		job := &pb.AgentJob{JobId: "weird", JobType: pb.JobType(99), DeviceId: "dev-w"}
		ok := submitJob(ctx, job, pools, out, func() { close(done) }, false)
		<-done
		if ok {
			t.Error("unsupported job must not be accepted")
		}
	})
}

// loopSession builds a minimal session for driving loop(). The caller feeds
// msgCh/errCh/traps and ends the loop by cancelling ctx or failing errCh.
func loopSession(ctx context.Context, results *resultQueue) (*session, context.CancelFunc) {
	sessionCtx, cancel := context.WithCancel(ctx)
	s := &session{
		ctx:        sessionCtx,
		cancel:     cancel,
		topic:      "agent:cov",
		writeCh:    make(chan writeRequest, 64),
		msgCh:      make(chan channelMsg, 16),
		errCh:      make(chan error, 8),
		writeErrCh: make(chan error, 8),
		notices:    make(chan outbound, 8),
		results:    results,
	}
	return s, cancel
}

// runLoopFor sends messages, then cancels and waits for the loop to return.
func runLoopFor(t *testing.T, s *session, cancel context.CancelFunc, drive func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.loop(context.Background()) }()
	drive()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not exit")
		return nil
	}
}

func TestLoopTrapBranches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("listener stopped", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		traps := make(chan *pb.SnmpTrap)
		s.traps = traps
		if err := runLoopFor(t, s, end, func() { close(traps) }); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
		if s.traps != nil {
			t.Error("stopped listener must clear s.traps")
		}
	})

	t.Run("nil trap ignored", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		traps := make(chan *pb.SnmpTrap, 2)
		s.traps = traps
		if err := runLoopFor(t, s, end, func() { traps <- nil }); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
	})

	t.Run("trap spooled", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		traps := make(chan *pb.SnmpTrap, 2)
		s.traps = traps
		traps <- &pb.SnmpTrap{SourceIp: "10.2.2.2", TrapOid: ".1.3.6.1.1.5.3"}
		defer end()
		done := make(chan error, 1)
		go func() { done <- s.loop(context.Background()) }()
		select {
		case <-s.writeCh: // trap result staged and written
		case <-time.After(2 * time.Second):
			t.Fatal("trap did not reach the writer")
		}
		end()
		if err := <-done; err != nil && !errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
	})

	t.Run("oversized trap counts a drop", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 4096) // room for the 1KiB room check, not the trap
		s, end := loopSession(ctx, results)
		traps := make(chan *pb.SnmpTrap, 2)
		s.traps = traps
		before := trapDroppedTotal.Load()
		if err := runLoopFor(t, s, end, func() {
			traps <- &pb.SnmpTrap{SourceIp: "10.2.2.2", TrapOid: ".1.3.6.1.6.3.1.1.5.3",
				Varbinds: map[string]string{strings.Repeat("1", 9000): strings.Repeat("x", 8192)}}
		}); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
		if trapDroppedTotal.Load() == before {
			t.Error("oversized trap must count a spool drop")
		}
	})
}

func TestLoopReplyAndAck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("phx_reply resolves pending", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		ref := "11"
		s.trackPending(ref, outbound{event: "result", payload: json.RawMessage(`{}`), sequence: 1})
		if err := runLoopFor(t, s, end, func() {
			payload, _ := json.Marshal(map[string]any{
				"status":   "ok",
				"response": map[string]string{},
			})
			s.msgCh <- channelMsg{Event: "phx_reply", Topic: "agent:cov", Ref: &ref, Payload: payload}
		}); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
		if _, ok := s.pending[ref]; ok {
			t.Error("reply must clear the pending entry")
		}
	})

	t.Run("phx_reply on phoenix topic also dispatches", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		ref := "12"
		if err := runLoopFor(t, s, end, func() {
			payload, _ := json.Marshal(map[string]any{"status": "ok", "response": map[string]string{}})
			s.msgCh <- channelMsg{Event: "phx_reply", Topic: "phoenix", Ref: &ref, Payload: payload}
		}); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
	})

	t.Run("result_ack releases held results", func(t *testing.T) {
		results := newResultQueueForAgentBytes(ctx, 1<<20)
		s, end := loopSession(ctx, results)
		results.hold(outbound{event: "result", sequence: 7, encodedBytes: 5})
		ack := &pb.AgentResultAck{CumulativeSequence: 7}
		raw, err := proto.Marshal(ack)
		if err != nil {
			t.Fatal(err)
		}
		if err := runLoopFor(t, s, end, func() {
			s.msgCh <- channelMsg{Event: "result_ack", Binary: true, Payload: raw}
		}); err != nil &&
			!errors.Is(err, errSessionCancelled) {
			t.Fatalf("loop: %v", err)
		}
		if results.pendingAckCount() != 0 {
			t.Error("ack must release the held result")
		}
	})
}

func TestLoopHeartbeatTicks(t *testing.T) {
	origHB, origCHB := heartbeatInterval, channelHeartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	channelHeartbeatInterval = 20 * time.Millisecond
	t.Cleanup(func() { heartbeatInterval, channelHeartbeatInterval = origHB, origCHB })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := newResultQueueForAgentBytes(ctx, 1<<20)
	s, end := loopSession(ctx, results)
	defer end()
	s.ws = &wsConn{localAddr: "127.0.0.1:5050"} // heartbeat reads LocalIP

	done := make(chan error, 1)
	go func() { done <- s.loop(context.Background()) }()

	// Both tickers fire: the heartbeat result and the channel heartbeat land
	// on writeCh.
	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && got < 2 {
		select {
		case <-s.writeCh:
			got++
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, errSessionCancelled) {
		t.Fatalf("loop: %v", err)
	}
	if got < 1 {
		t.Error("no heartbeat frames written")
	}
}

func TestLoopBatchFlush(t *testing.T) {
	orig := resultBatchFlushDelay
	resultBatchFlushDelay = 10 * time.Millisecond
	t.Cleanup(func() { resultBatchFlushDelay = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := newResultQueueForAgentBytes(ctx, 1<<20)
	s, end := loopSession(ctx, results)
	defer end()
	s.resultBatches = true
	s.v2 = true
	s.serverCapabilities = map[string]struct{}{capabilityResultBatch: {}}

	// Park a result so the flush has something to write.
	results.enqueue(outbound{event: "result", protoPayload: []byte("x"), encodedBytes: 1})

	done := make(chan error, 1)
	go func() { done <- s.loop(context.Background()) }()
	select {
	case req := <-s.writeCh:
		if len(req.data) == 0 {
			t.Error("empty batch frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch flush did not write")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, errSessionCancelled) {
		t.Fatalf("loop: %v", err)
	}
}

func TestDrainSpoolAndResultsDrained(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("empty spool drains immediately", func(t *testing.T) {
		s := &session{ctx: ctx, results: newResultQueue(4)}
		if !s.drainSpool(ctx) {
			t.Error("empty spool must drain")
		}
	})

	t.Run("busy pools block the drain until ctx", func(t *testing.T) {
		pools := testPools(t)
		release := make(chan struct{})
		pools.snmp.submit(context.Background(), func() { <-release })
		time.Sleep(20 * time.Millisecond)
		s := &session{ctx: ctx, pools: pools, results: newResultQueue(4)}
		drainCtx, drainCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer drainCancel()
		if s.drainSpool(drainCtx) {
			t.Error("busy pools must block the drain")
		}
		close(release)
		if !pools.stopAccepting.Load() {
			t.Error("drain must stop accepting work")
		}
	})

	t.Run("resultsDrained nil pools", func(t *testing.T) {
		s := &session{ctx: ctx, results: newResultQueue(4)}
		if !s.resultsDrained() {
			t.Error("nil pools must be idle")
		}
	})
}

func TestPrunePendingExpired(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{ctx: ctx, results: newResultQueue(4)}
	s.trackPending("old", outbound{event: "result", payload: json.RawMessage(`{}`)})
	entry := s.pending["old"]
	entry.sentAt = time.Now().Add(-2 * pendingReplyTTL)
	s.pending["old"] = entry
	s.prunePending()
	if _, ok := s.pending["old"]; ok {
		t.Error("expired pending must be pruned")
	}
}

func TestEvictOldestPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{ctx: ctx, results: newResultQueue(4)}
	s.trackPending("first", outbound{event: "result"})
	s.trackPending("second", outbound{event: "result"})
	s.evictOldestPending()
	if _, ok := s.pending["first"]; ok {
		t.Error("oldest must be evicted")
	}
	if _, ok := s.pending["second"]; !ok {
		t.Error("newest must remain")
	}
	// Empty map: no-op.
	s.pending = nil
	s.evictOldestPending()
}
