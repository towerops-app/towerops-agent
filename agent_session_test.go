// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// runAgent connects with local recurring scheduling.
func runAgent(ctx context.Context, wsURL, token string, traps <-chan *pb.SnmpTrap) {
	runAgentWithScheduling(ctx, wsURL, token, traps, true)
}

// runSession runs one WebSocket session with local recurring scheduling and
// a fresh spool.
func runSession(ctx context.Context, baseURL, token string, traps <-chan *pb.SnmpTrap) error {
	return runSessionWithResults(ctx, baseURL, token, traps, newResultQueueForAgent(ctx, resultQueueSize))
}

func runSessionWithResults(
	ctx context.Context,
	baseURL, token string,
	traps <-chan *pb.SnmpTrap,
	results *resultQueue,
) error {
	return runSessionWithResultsAndScheduling(ctx, baseURL, token, traps, results, true)
}

// joinFrameTopic reads the agent's phx_join frame and returns its topic so a
// fake server can reply on it. Returns "" when the frame cannot be read.
func joinFrameTopic(conn net.Conn) string {
	data, err := readMaskedFrame(conn)
	if err != nil {
		return ""
	}
	var join channelMsg
	_ = json.Unmarshal(data, &join)
	return join.Topic
}

// SIGTERM while a self-update holds a drained session: the loop runs the
// shutdown drain, cancelActiveUpdate makes the update return, and
// abortDrainedSession must not cancel the session I/O context the shutdown
// drain is still writing through.
func TestAbortDrainedSessionDuringShutdownKeepsShutdownDrain(t *testing.T) {
	t.Cleanup(func() { drainedSession.Store(nil) })
	pools := testPools(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobCtx, jobCancel := context.WithCancel(context.Background())
	s := &session{
		ctx:        ctx,
		cancel:     cancel,
		jobCtx:     jobCtx,
		jobCancel:  jobCancel,
		results:    newResultQueue(4),
		pools:      pools,
		scheduler:  pools.scheduler,
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		abortCh:    make(chan error, 1),
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), time.Second)
	defer drainCancel()
	if !s.drainResults(drainCtx) {
		t.Fatal("drain failed")
	}

	// Process shutdown cancels the agent context, and with it jobCtx.
	jobCancel()
	abortDrainedSession()

	if s.ctx.Err() != nil {
		t.Fatal("abort cancelled the session I/O context during process shutdown")
	}
	if len(s.abortCh) != 0 {
		t.Fatal("abort published errSelfUpdateAborted during process shutdown")
	}
	if drainedSession.Load() != nil {
		t.Fatal("drained session was not cleared")
	}
}

// The server replies only to rejected results, so acked results stay in
// pending until the TTL sweep. The map is capped by count: the oldest entry
// goes first.
func TestTrackPendingCapsEntriesByCount(t *testing.T) {
	s := &session{results: newResultQueue(4)}
	total := maxPendingResults + 10
	for i := range total {
		ref := strconv.Itoa(i)
		s.trackPending(ref, outbound{event: "result"})
		s.pending[ref] = pendingResult{result: s.pending[ref].result, sentAt: time.Now(), seq: s.pending[ref].seq}
	}
	if got := len(s.pending); got != maxPendingResults {
		t.Fatalf("pending holds %d entries, want %d", got, maxPendingResults)
	}
	for i := range 10 {
		if _, ok := s.pending[strconv.Itoa(i)]; ok {
			t.Fatalf("oldest entry %d survived the cap", i)
		}
	}
	if _, ok := s.pending[strconv.Itoa(total-1)]; !ok {
		t.Fatal("newest entry was evicted")
	}
}

// "overloaded" means the server's ingest queue is full. Re-sending at once
// hits the same full queue, so the retry waits overloadRetryDelay.
func TestHandleResultReplyDelaysOverloadedRetry(t *testing.T) {
	orig := overloadRetryDelay
	t.Cleanup(func() { overloadRetryDelay = orig })
	overloadRetryDelay = 100 * time.Millisecond

	results := newResultQueue(4)
	s := &session{results: results}
	s.trackPending("5", outbound{event: "result", payload: json.RawMessage(`{"binary":"e30="}`)})
	ref := "5"
	start := time.Now()
	s.handleResultReply(channelMsg{
		Ref:     &ref,
		Payload: json.RawMessage(`{"status":"error","response":{"reason":"overloaded"}}`),
	})

	if len(results.items) != 0 {
		t.Fatal("overloaded result was requeued immediately")
	}
	select {
	case queued := <-results.items:
		if elapsed := time.Since(start); elapsed < overloadRetryDelay {
			t.Fatalf("retry arrived after %v, want at least %v", elapsed, overloadRetryDelay)
		}
		if queued.attempts != 1 {
			t.Fatalf("requeued attempts = %d, want 1", queued.attempts)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("overloaded result was never requeued")
	}
}

// The delayed retry reports a full spool instead of blocking or panicking.
func TestDelayedRetryDroppedWhenSpoolFull(t *testing.T) {
	logs := agtCaptureLogs(t)
	results := newResultQueue(1)
	if !results.enqueue(outbound{event: "filler"}) {
		t.Fatal("seed enqueue failed")
	}
	results.enqueueAfter(outbound{event: "result"}, time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for !logs.has("result retry dropped, spool full") {
		if time.Now().After(deadline) {
			t.Fatalf("no spool-full report\nlogged:\n%s", logs.dump())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// "Invalid message" is a decode failure on the server: the same bytes fail
// the same way, so the result is dropped instead of re-sent.
func TestHandleResultReplyDropsInvalidMessage(t *testing.T) {
	results := newResultQueue(4)
	s := &session{results: results}
	s.trackPending("6", outbound{event: "result", payload: json.RawMessage(`{"binary":"e30="}`)})
	ref := "6"
	s.handleResultReply(channelMsg{
		Ref:     &ref,
		Payload: json.RawMessage(`{"status":"error","response":{"reason":"Invalid message: decode_error"}}`),
	})
	select {
	case queued := <-results.items:
		t.Fatalf("invalid-message result was requeued: %+v", queued)
	default:
	}
}

// The self-update drain stops new recurring ticks but lets a running tick
// finish with a live context, so its result reaches the spool.
func TestDrainResultsLetsRunningRecurringJobFinish(t *testing.T) {
	pools := testPools(t)
	results := newResultQueue(4)
	s := &session{results: results, pools: pools, scheduler: pools.scheduler}
	t.Cleanup(func() { drainedSession.CompareAndSwap(s, nil) })

	started := make(chan struct{})
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	var ticks atomic.Int32
	spec := scheduleSpec{
		id:       "poll:drain",
		interval: 20 * time.Millisecond,
		payload:  &pb.AgentJob{JobId: "poll:drain"},
		submit: func(ctx context.Context, done func()) bool {
			return pools.snmp.submitMode(ctx, func() {
				defer done()
				if ticks.Add(1) == 1 {
					close(started)
					<-release
					ctxErr <- ctx.Err()
				}
			}, true)
		},
	}
	pools.scheduler.replace(&pools.scheduler.jobs, []scheduleSpec{spec})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("recurring tick never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	drained := make(chan bool, 1)
	go func() { drained <- s.drainResults(ctx) }()

	select {
	case <-drained:
		t.Fatal("drain finished while a recurring tick was running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-ctxErr; err != nil {
		t.Fatalf("running recurring tick saw ctx error %v, want a live context", err)
	}
	if !<-drained {
		t.Fatal("drain returned false after the tick finished")
	}

	// Paused: no further ticks, and a new inventory is refused.
	time.Sleep(100 * time.Millisecond)
	if got := ticks.Load(); got != 1 {
		t.Fatalf("scheduler ran %d ticks after the drain paused it, want 1", got)
	}
	other := spec
	other.id = "poll:other"
	pools.scheduler.replace(&pools.scheduler.jobs, []scheduleSpec{spec, other})
	pools.scheduler.mu.Lock()
	_, added := pools.scheduler.jobs["poll:other"]
	pools.scheduler.mu.Unlock()
	if added {
		t.Fatal("paused scheduler accepted a new inventory")
	}
}

// A recurring tick or check refused by a paused pool sends no "pool
// overloaded" notice: the refusal is the drain, not saturation.
func TestPausedPoolRefusalSendsNoOverloadNotice(t *testing.T) {
	origJitter := dispatchJitterMax
	t.Cleanup(func() { dispatchJitterMax = origJitter })
	dispatchJitterMax = 0

	submits := map[string]func(*jobPools, func()) bool{
		"job": func(pools *jobPools, done func()) bool {
			pools.snmp.pause()
			job := &pb.AgentJob{JobId: "poll:paused", JobType: pb.JobType_POLL, DeviceId: "d1"}
			return submitJob(context.Background(), job, pools, testQueue(), done, true)
		},
		"check": func(pools *jobPools, done func()) bool {
			pools.checks.pause()
			return submitCheck(context.Background(), &pb.Check{Id: "c1"}, pools, testQueue(), done, true)
		},
	}
	for name, submit := range submits {
		t.Run(name, func(t *testing.T) {
			pools := testPools(t)
			notices := make(chan outbound, 1)
			pools.notices = notices
			var done atomic.Int32
			if submit(pools, func() { done.Add(1) }) {
				t.Fatal("paused pool accepted the submission")
			}
			if got := done.Load(); got != 1 {
				t.Fatalf("done called %d times, want 1", got)
			}
			select {
			case notice := <-notices:
				t.Fatalf("drain refusal sent an overload notice: %s", notice.payload)
			default:
			}
		})
	}
}

// An unsupported job type still releases the caller's done callback.
func TestSubmitJobUnsupportedTypeCallsDone(t *testing.T) {
	pools := testPools(t)
	var done atomic.Int32
	job := &pb.AgentJob{JobId: "x", JobType: pb.JobType(999)}
	if submitJob(context.Background(), job, pools, testQueue(), func() { done.Add(1) }, false) {
		t.Fatal("unsupported job type was accepted")
	}
	if got := done.Load(); got != 1 {
		t.Fatalf("done called %d times, want 1", got)
	}
}

// Frames that arrive while the process shuts down are logged as a shutdown
// refusal; only the self-update drain marks the inventory rejected.
func TestHandleMessageRefusesDuringShutdownWithoutDrainNotice(t *testing.T) {
	for _, event := range []string{"jobs", "check_jobs", "discovery_job"} {
		t.Run(event, func(t *testing.T) {
			logs := agtCaptureLogs(t)
			pools := testPools(t)
			pools.stopAccepting.Store(true)
			out := testQueue()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			end, err := handleMessage(ctx,
				channelMsg{Topic: "agent:test", Event: event, Payload: makeJobPayload()},
				"agent:test", pools, out)
			if end || err != nil {
				t.Fatalf("handleMessage = (%v, %v), want (false, nil)", end, err)
			}
			if logs.has("self-update drain") {
				t.Fatalf("shutdown refusal blamed the self-update drain\nlogged:\n%s", logs.dump())
			}
			if !logs.has("during shutdown") {
				t.Fatalf("no shutdown refusal logged\nlogged:\n%s", logs.dump())
			}
			if rejected, _ := pools.rejectedInventory.Load().(string); rejected != "" {
				t.Fatalf("shutdown refusal marked inventory %q rejected", rejected)
			}
		})
	}
}

// A frame addressed to another channel topic is ignored, even a restart.
func TestHandleMessageIgnoresOtherTopic(t *testing.T) {
	end, err := handleMessage(context.Background(),
		channelMsg{Topic: "agent:other", Event: "restart", Payload: json.RawMessage(`{}`)},
		"agent:mine", testPools(t), testQueue())
	if end || err != nil {
		t.Fatalf("handleMessage = (%v, %v), want (false, nil)", end, err)
	}
}

// The join reply must come back on the topic the agent joined.
func TestValidateJoinReplyRejectsWrongTopic(t *testing.T) {
	data, err := json.Marshal(channelMsg{
		Topic:   "agent:other",
		Event:   "phx_reply",
		Payload: json.RawMessage(`{"status":"ok"}`),
		Ref:     new("1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateJoinReply(data, "agent:mine"); err == nil || !strings.Contains(err.Error(), "topic") {
		t.Fatalf("validateJoinReply() error = %v, want a topic mismatch", err)
	}
}

// The "flushed" count is the number of results acked during the shutdown
// drain, including ones queued after the drain started.
func TestDrainForShutdownCountsAckedResults(t *testing.T) {
	logs := agtCaptureLogs(t)
	results := newResultQueue(4)
	pools := testPools(t)
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{ctx: sessionCtx, cancel: cancel, results: results, pools: pools, scheduler: pools.scheduler}

	first := outbound{event: "result"}
	if !results.enqueue(first) {
		t.Fatal("enqueue failed")
	}
	inFlight := <-results.items // one write already in flight at drain start
	if !results.enqueue(outbound{event: "result"}) {
		t.Fatal("enqueue failed")
	}

	done := make(chan struct{})
	go s.drainForShutdown(done)
	// drainSpool stops intake after the drain records its starting count.
	for !pools.stopAccepting.Load() {
		time.Sleep(time.Millisecond)
	}

	_ = s.resolveInFlight(&inFlightWrite{result: inFlight, spooled: true}, nil)
	queued := <-results.items
	_ = s.resolveInFlight(&inFlightWrite{result: queued, spooled: true}, nil)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown drain did not finish")
	}
	if !logs.has("flushed=2") {
		t.Fatalf("flushed count does not match the 2 acked results\nlogged:\n%s", logs.dump())
	}
}
