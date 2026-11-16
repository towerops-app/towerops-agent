// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// phaseClock is a deterministic wall-clock: tests move Now() by hand and
// fire the returned timers, so phase arithmetic and lag are exact.
type phaseClock struct {
	mu       sync.Mutex
	now      time.Time
	requests chan phaseTimerRequest
}

type phaseTimerRequest struct {
	interval time.Duration
	timer    *phaseTimer
}

type phaseTimer struct {
	ch chan time.Time
}

func newPhaseClock(start time.Time) *phaseClock {
	return &phaseClock{now: start, requests: make(chan phaseTimerRequest, 256)}
}

func (c *phaseClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *phaseClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *phaseClock) NewTimer(interval time.Duration) scheduleTimer {
	timer := &phaseTimer{ch: make(chan time.Time, 1)}
	c.requests <- phaseTimerRequest{interval: interval, timer: timer}
	return timer
}

func (t *phaseTimer) C() <-chan time.Time { return t.ch }
func (t *phaseTimer) Stop() bool          { return true }

func nextPhaseTimer(t *testing.T, clock *phaseClock) phaseTimerRequest {
	t.Helper()
	select {
	case request := <-clock.requests:
		return request
	case <-time.After(time.Second):
		t.Fatal("scheduler did not create a timer")
		return phaseTimerRequest{}
	}
}

func firePhaseTimer(t *testing.T, request phaseTimerRequest) {
	t.Helper()
	select {
	case request.timer.ch <- time.Time{}:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not receive the timer tick")
	}
}

// phaseRun is a blocking tick handle: submit reports the tick and holds it
// open until the test releases it.
type phaseRun struct {
	id   string
	done chan struct{}
}

func newPhaseSpec(id, payload string, interval time.Duration, runs chan<- phaseRun) scheduleSpec {
	return scheduleSpec{
		id:       id,
		interval: interval,
		payload:  &pb.Check{Id: id, CheckType: payload},
		submit: func(ctx context.Context, done func()) bool {
			run := phaseRun{id: id, done: make(chan struct{})}
			select {
			case runs <- run:
			case <-ctx.Done():
				return false
			}
			select {
			case <-run.done:
				done()
				return true
			case <-ctx.Done():
				<-run.done
				done()
				return true
			}
		},
	}
}

func (r phaseRun) release() { close(r.done) }

func nextPhaseRun(t *testing.T, runs <-chan phaseRun) phaseRun {
	t.Helper()
	select {
	case run := <-runs:
		return run
	case <-time.After(time.Second):
		t.Fatal("scheduler did not submit the tick")
		return phaseRun{}
	}
}

func assertNoPhaseRun(t *testing.T, runs <-chan phaseRun) {
	t.Helper()
	select {
	case run := <-runs:
		t.Fatalf("scheduler submitted %s unexpectedly", run.id)
	default:
	}
}

// waitForSkippedTicks waits for the scheduler's asynchronous tick loop to
// publish a skip. The counter is updated on a separate goroutine from the
// timer fire.
func waitForSkippedTicks(t *testing.T, want uint64) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for processMetrics.skippedTicks.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("skipped ticks = %d, want %d", processMetrics.skippedTicks.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// saveScheduleMetrics restores the process-wide metric windows so tests stay
// independent and deterministic.
func saveScheduleMetrics(t *testing.T) (restore func()) {
	t.Helper()
	processMetrics.scheduleLagMu.Lock()
	savedLag := append([]uint64(nil), processMetrics.scheduleLag...)
	savedPos, savedFull := processMetrics.scheduleLagPos, processMetrics.scheduleLagFull
	processMetrics.scheduleLag = nil
	processMetrics.scheduleLagPos = 0
	processMetrics.scheduleLagFull = false
	processMetrics.scheduleLagMu.Unlock()
	savedSkipped := processMetrics.skippedTicks.Load()
	processMetrics.skippedTicks.Store(0)
	return func() {
		processMetrics.scheduleLagMu.Lock()
		processMetrics.scheduleLag = savedLag
		processMetrics.scheduleLagPos = savedPos
		processMetrics.scheduleLagFull = savedFull
		processMetrics.scheduleLagMu.Unlock()
		processMetrics.skippedTicks.Store(savedSkipped)
	}
}

// B3/D3: the phase is hash(id) mod interval and the next run is the first
// aligned instant after now; the alignment survives reconnects and restarts.
func TestWallClockPhaseDelayAlignsAcrossReconnects(t *testing.T) {
	interval := time.Hour
	for _, id := range []string{"poll:device-1", "ping:device-2", "ssl:example.com"} {
		base := time.Unix(1_700_000_000, 0)
		phase := schedulePhase(id, interval)
		if phase <= 0 || phase >= interval {
			t.Fatalf("schedulePhase(%q) = %s, want within (0, %s)", id, phase, interval)
		}

		delay := wallClockPhaseDelay(id, interval, base)
		planned := base.Add(delay)
		if got := (planned.UnixNano() - phase.Nanoseconds()) % int64(interval); got != 0 {
			t.Fatalf("planned instant %s is %s off the %s phase", planned, time.Duration(got), phase)
		}

		// A reconnect (or any restart) at an arbitrary later wall time lands
		// on the same phase grid.
		reconnect := planned.Add(17*time.Minute + 3*interval)
		next := reconnect.Add(wallClockPhaseDelay(id, interval, reconnect))
		if next.Sub(planned)%interval != 0 {
			t.Fatalf("reconnect next run %s is not a whole interval from %s", next, planned)
		}
	}
}

// B3: the spread covers the whole interval, not just the first 60 seconds.
func TestWallClockPhaseSpreadCoversInterval(t *testing.T) {
	interval := time.Hour
	base := time.Unix(1_700_000_000, 0)
	beyondLegacyCap := 0
	distinct := make(map[time.Duration]bool)
	for i := range 200 {
		id := fmt.Sprintf("poll:device-%d", i)
		delay := wallClockPhaseDelay(id, interval, base)
		distinct[delay] = true
		if delay >= maxFirstTickDelay {
			beyondLegacyCap++
		}
	}
	if len(distinct) < 100 {
		t.Fatalf("phase spread collapsed to %d distinct offsets", len(distinct))
	}
	if beyondLegacyCap < 150 {
		t.Fatalf("only %d of 200 phases exceed the legacy 60s cap", beyondLegacyCap)
	}
}

// B3/D3: a wall-clock entry waits until its planned phase, records lag as
// actual start minus planned start, and then repeats on the phase grid.
func TestSchedulerRunsOnWallClockPhaseAndRecordsLag(t *testing.T) {
	restore := saveScheduleMetrics(t)
	defer restore()

	base := time.Unix(1_700_000_000, 0)
	clock := newPhaseClock(base)
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan phaseRun, 4)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		newPhaseSpec("job-1", "phase", time.Hour, runs),
	})

	timer := nextPhaseTimer(t, clock)
	expected := wallClockPhaseDelay("job-1", time.Hour, base)
	if timer.interval != expected {
		t.Fatalf("first tick delay = %s, want the %s phase", timer.interval, expected)
	}

	// Lag: the agent reconnects late, the clock is already 5s past the
	// planned instant when the timer fires.
	clock.advance(expected + 5*time.Second)
	firePhaseTimer(t, timer)
	first := nextPhaseRun(t, runs)

	if ms, ok := processMetrics.scheduleLagP95(); !ok || ms != 5000 {
		t.Fatalf("schedule lag p95 = %dms (found %t), want 5000ms", ms, ok)
	}

	nextTimer := nextPhaseTimer(t, clock)
	// The phase grid is preserved: the next planned instant is one whole
	// interval after the missed phase, so the wait shrinks by the lag.
	if want := time.Hour - 5*time.Second; nextTimer.interval != want {
		t.Fatalf("cycle timer = %s, want %s from the phase grid", nextTimer.interval, want)
	}

	// Release and wait for the timer recreated after the scheduler observes
	// the finished marker, then advance to that preserved phase.
	first.release()
	newTimer := nextPhaseTimer(t, clock)
	clock.advance(time.Hour)
	firePhaseTimer(t, newTimer)
	second := nextPhaseRun(t, runs)
	second.release()

	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

// D3: a tick that fires while the previous run of the same job is still
// active is skipped and counted, never overlapped or silently stretched.
func TestSchedulerSkipsOverlappingTicks(t *testing.T) {
	restore := saveScheduleMetrics(t)
	defer restore()

	base := time.Unix(1_700_000_000, 0)
	clock := newPhaseClock(base)
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan phaseRun, 4)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		newPhaseSpec("job-1", "phase", time.Hour, runs),
	})
	timer := nextPhaseTimer(t, clock)
	clock.advance(wallClockPhaseDelay("job-1", time.Hour, base))
	firePhaseTimer(t, timer)
	first := nextPhaseRun(t, runs)

	// One whole interval later the first run is still going: skip and count.
	next := nextPhaseTimer(t, clock)
	if next.interval != time.Hour {
		t.Fatalf("cycle timer = %s, want 1h", next.interval)
	}
	clock.advance(time.Hour)
	firePhaseTimer(t, next)
	assertNoPhaseRun(t, runs)
	waitForSkippedTicks(t, 1)
	if skipped := processMetrics.skippedTicks.Load(); skipped != 1 {
		t.Fatalf("skipped ticks = %d, want 1", skipped)
	}

	// The scheduler created this phase's timer while the first run was still
	// active. Drain it, then wait for the timer it creates only after it has
	// observed the finished marker; firing the stale timer could race the
	// finished branch and count a second skip.
	first.release()
	_ = nextPhaseTimer(t, clock)
	clean := nextPhaseTimer(t, clock)
	firePhaseTimer(t, clean)
	second := nextPhaseRun(t, runs)
	if skipped := processMetrics.skippedTicks.Load(); skipped != 1 {
		t.Fatalf("skipped ticks = %d after a clean run, want 1", skipped)
	}
	second.release()

	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

// B4: small in-place changes run immediately; a fleet-wide push keeps every
// job's existing phase.
func TestSchedulerImmediateOnlyForSmallChanges(t *testing.T) {
	if got := immediateChangeSlots(1); got != 1 {
		t.Fatalf("immediateChangeSlots(1) = %d, want 1", got)
	}
	if got := immediateChangeSlots(3000); got != 150 {
		t.Fatalf("immediateChangeSlots(3000) = %d, want 150", got)
	}

	base := time.Unix(1_700_000_000, 0)
	clock := newPhaseClock(base)
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan phaseRun, 8)

	specs := make([]scheduleSpec, 0, 40)
	for i := range 40 {
		specs = append(specs, newPhaseSpec(fmt.Sprintf("job-%d", i), "initial", time.Hour, runs))
	}
	scheduler.replace(&scheduler.jobs, specs)

	// A whole fresh inventory is not a "change": nothing runs immediately.
	for id, entry := range scheduler.jobs {
		if entry.stagedImmediate {
			t.Fatalf("fresh inventory staged %s for an immediate run", id)
		}
	}

	// Fleet-wide credential rotation: every payload changes, so the new
	// entries must keep their phases instead of aligning on now.
	fleet := make([]scheduleSpec, 0, 40)
	for i := range 40 {
		fleet = append(fleet, newPhaseSpec(fmt.Sprintf("job-%d", i), "fleet", time.Hour, runs))
	}
	scheduler.replace(&scheduler.jobs, fleet)
	for id, entry := range scheduler.jobs {
		if entry.stagedImmediate {
			t.Fatalf("fleet-wide change staged %s for an immediate run", id)
		}
	}

	// One operator fix on the same inventory runs as soon as its predecessor
	// releases the ID; the other 39 entries are untouched.
	fixed := make([]scheduleSpec, 0, 40)
	for i := range 40 {
		payload := "fleet"
		if i == 0 {
			payload = "fixed"
		}
		fixed = append(fixed, newPhaseSpec(fmt.Sprintf("job-%d", i), payload, time.Hour, runs))
	}
	fleetSnapshot := make(map[string]*scheduleEntry, len(scheduler.jobs))
	scheduler.mu.Lock()
	for id, entry := range scheduler.jobs {
		fleetSnapshot[id] = entry
	}
	scheduler.mu.Unlock()
	scheduler.replace(&scheduler.jobs, fixed)
	var changedEntry *scheduleEntry
	for id, entry := range scheduler.jobs {
		if id == "job-0" {
			changedEntry = entry
			continue
		}
		if fleetSnapshot[id] != entry {
			t.Fatalf("unchanged assignment %s was replaced by the small change", id)
		}
		if entry.stagedImmediate {
			t.Fatalf("unchanged assignment %s staged for an immediate run", id)
		}
	}
	if changedEntry == nil || !changedEntry.stagedImmediate {
		t.Fatalf("small change staged = %+v, want job-0 immediate", changedEntry)
	}
	// An immediate change starts directly; it does not create a zero-delay
	// phase timer.
	changedRun := nextPhaseRun(t, runs)
	if changedRun.id != "job-0" {
		t.Fatalf("immediate run = %s, want job-0", changedRun.id)
	}
	changedRun.release()

	scheduler.cancelAll()
	if !scheduler.wait(5 * time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

// B8: fingerprints are 32-byte SHA-256 digests, not serialized payloads.
func TestPayloadFingerprintIsSHA256(t *testing.T) {
	first := payloadFingerprint(&pb.AgentJob{JobId: "poll:device-1"})
	if len(first) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(first))
	}
	same := payloadFingerprint(&pb.AgentJob{JobId: "poll:device-1"})
	if string(same) != string(first) {
		t.Fatal("identical payloads produced different fingerprints")
	}
	changed := payloadFingerprint(&pb.AgentJob{JobId: "poll:device-2"})
	if string(changed) == string(first) {
		t.Fatal("different payloads produced the same fingerprint")
	}
}
