// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

func TestSchedulerNowFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The manual clock has no Now(): now() falls back to wall time.
	s := newRecurringScheduler(ctx, newManualScheduleClock())
	defer s.cancelAll()
	if got := s.now(); got.IsZero() {
		t.Error("now() must fall back to the real clock")
	}
	if s.wallClock() {
		t.Error("manual clock must not report wall time")
	}
}

func TestReplaceJobsDropsInvalid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newRecurringScheduler(ctx, newManualScheduleClock())
	defer s.cancelAll()
	pools := &jobPools{}
	out := newResultQueue(4)
	s.replaceJobs([]*pb.AgentJob{
		nil,
		{JobId: ""},
		{JobId: "ok-job", IntervalSeconds: 3600},
	}, pools, out)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.jobs) != 1 {
		t.Errorf("jobs = %d, want 1", len(s.jobs))
	}
}

func TestRunOncePaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("paused blocks until cancel", func(t *testing.T) {
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		s.paused.Store(true)
		subCtx, subCancel := context.WithCancel(ctx)
		done := make(chan bool, 1)
		go func() { done <- s.runOnce(subCtx, scheduleSpec{id: "p"}) }()
		time.Sleep(10 * time.Millisecond)
		subCancel()
		if ok := <-done; ok {
			t.Error("cancelled pause must return false")
		}
	})

	t.Run("rejected submission waits for interval", func(t *testing.T) {
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		clock := s.clock.(*manualScheduleClock)
		spec := scheduleSpec{
			id:       "rej",
			interval: time.Hour,
			submit:   func(ctx context.Context, done func()) bool { return false },
		}
		res := make(chan bool, 1)
		go func() { res <- s.runOnce(ctx, spec) }()
		var timer *manualScheduleTimer
		select {
		case req := <-clock.requests:
			timer = req.timer
		case <-time.After(time.Second):
			t.Fatal("timer not requested")
		}
		timer.ch <- time.Now()
		if ok := <-res; !ok {
			t.Error("interval tick after rejection must return true")
		}
	})

	t.Run("rejected submission cancelled", func(t *testing.T) {
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		spec := scheduleSpec{
			id:       "rejc",
			interval: time.Hour,
			submit:   func(ctx context.Context, done func()) bool { return false },
		}
		subCtx, subCancel := context.WithCancel(ctx)
		res := make(chan bool, 1)
		go func() { res <- s.runOnce(subCtx, spec) }()
		time.Sleep(10 * time.Millisecond)
		subCancel()
		if ok := <-res; ok {
			t.Error("cancel during rejected wait must return false")
		}
	})

	t.Run("accepted tick completes and returns", func(t *testing.T) {
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		clock := s.clock.(*manualScheduleClock)
		spec := scheduleSpec{
			id:       "acc",
			interval: time.Hour,
			submit: func(ctx context.Context, done func()) bool {
				go done()
				return true
			},
		}
		res := make(chan bool, 1)
		go func() { res <- s.runOnce(ctx, spec) }()
		var timer *manualScheduleTimer
		select {
		case req := <-clock.requests:
			timer = req.timer
		case <-time.After(time.Second):
			t.Fatal("timer not requested")
		}
		timer.ch <- time.Now()
		if ok := <-res; !ok {
			t.Error("completed tick must return true")
		}
	})

	t.Run("cancel waits for the running task", func(t *testing.T) {
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		release := make(chan struct{})
		spec := scheduleSpec{
			id:       "cwait",
			interval: time.Hour,
			submit: func(ctx context.Context, done func()) bool {
				go func() {
					<-release
					done()
				}()
				return true
			},
		}
		subCtx, subCancel := context.WithCancel(ctx)
		res := make(chan bool, 1)
		go func() { res <- s.runOnce(subCtx, spec) }()
		time.Sleep(10 * time.Millisecond)
		subCancel()
		select {
		case <-res:
			t.Fatal("cancel must wait for the task")
		case <-time.After(20 * time.Millisecond):
		}
		close(release)
		if ok := <-res; ok {
			t.Error("cancelled run must return false")
		}
	})

	t.Run("rejected tick returns immediately", func(t *testing.T) {
		// runTick's !accepted early-return, driven directly: the goroutine
		// timing in runOnce made this arm flaky on loaded CI.
		s := newRecurringScheduler(ctx, newManualScheduleClock())
		defer s.cancelAll()
		spec := scheduleSpec{
			id:       "rtrej",
			interval: time.Hour,
			submit:   func(ctx context.Context, done func()) bool { return false },
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.runTick(ctx, spec, false, time.Time{})
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("rejected tick must return without waiting")
		}
	})
}

func TestRunLoopSkipsTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newRecurringScheduler(ctx, newManualScheduleClock())
	defer s.cancelAll()
	clock := s.clock.(*manualScheduleClock)

	release := make(chan struct{})
	submitted := make(chan struct{}, 8)
	spec := scheduleSpec{
		id:       "skip",
		interval: time.Hour,
		submit: func(ctx context.Context, done func()) bool {
			submitted <- struct{}{}
			go func() {
				<-release
				done()
			}()
			return true
		},
	}
	s.replace(&s.jobs, []scheduleSpec{spec})

	// First tick: the timer fires, the job starts and stays busy.
	var first *manualScheduleTimer
	select {
	case req := <-clock.requests:
		first = req.timer
	case <-time.After(time.Second):
		t.Fatal("timer")
	}
	first.ch <- time.Now()
	<-submitted

	// Second tick while the job is still running: the phase is skipped and
	// skippedTicks counts it.
	var second *manualScheduleTimer
	select {
	case req := <-clock.requests:
		second = req.timer
	case <-time.After(time.Second):
		t.Fatal("second timer")
	}
	before := processMetrics.skippedTicks.Load()
	second.ch <- time.Now()
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && processMetrics.skippedTicks.Load() == before {
		time.Sleep(5 * time.Millisecond)
	}
	if processMetrics.skippedTicks.Load() == before {
		t.Error("active tick must be skipped and counted")
	}
}

func TestRunLoopPauseBlocksActiveTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newRecurringScheduler(ctx, newManualScheduleClock())
	defer s.cancelAll()
	clock := s.clock.(*manualScheduleClock)

	release := make(chan struct{})
	submitted := make(chan struct{}, 1)
	spec := scheduleSpec{
		id:       "pause",
		interval: time.Hour,
		submit: func(ctx context.Context, done func()) bool {
			submitted <- struct{}{}
			go func() {
				<-release
				done()
			}()
			return true
		},
	}
	s.replace(&s.jobs, []scheduleSpec{spec})
	select {
	case req := <-clock.requests:
		req.timer.ch <- time.Now()
	case <-time.After(time.Second):
		t.Fatal("timer")
	}
	<-submitted
	// Pause while the tick is active: the entry waits for the running task.
	s.pause()
	s.cancelAll()
	close(release)
}

func TestRunOncePlannedInPast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := newPhaseClock(time.Now())
	s := newRecurringScheduler(ctx, clock)
	defer s.cancelAll()

	submitted := make(chan struct{}, 2)
	spec := scheduleSpec{
		id:       "past",
		interval: time.Hour,
		submit: func(ctx context.Context, done func()) bool {
			submitted <- struct{}{}
			done()
			return true
		},
	}
	s.replace(&s.jobs, []scheduleSpec{spec})
	// The first timer request is the phase delay; jump the clock well past it
	// so wait < 0 clamps to zero and the phase runs immediately.
	req := <-clock.requests
	req.timer.ch <- time.Now()
	clock.advance(2 * time.Hour)
	// The loop then plans the next phase and may compute a negative wait
	// before the submit; give the run a beat.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-submitted:
			return
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatal("tick did not run")
}

func TestPollerDefaultsAndSizes(t *testing.T) {
	if got := resultSpoolByteLimit(); got != defaultResultSpoolBytes {
		t.Errorf("spool limit = %d", got)
	}
	if got := disconnectGracePeriod(); got != 15*time.Minute {
		t.Errorf("grace = %v", got)
	}
	if got := snmpPoolSize(); got != 100 {
		t.Errorf("snmp pool = %d", got)
	}
	if got := mikrotikPoolSize(); got != 20 {
		t.Errorf("mikrotik pool = %d", got)
	}
	if got := pingPoolSize(); got != 50 {
		t.Errorf("ping pool = %d", got)
	}
	if got := checksPoolSize(); got != 50 {
		t.Errorf("checks pool = %d", got)
	}
	if got := backupPoolSize(); got != 8 {
		t.Errorf("backup pool = %d", got)
	}
}

func TestPollerLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := newResultQueue(8)

	poller := newProcessPoller(ctx, results, false)
	if poller == nil {
		t.Fatal("poller")
	}

	// A nil update is ignored.
	poller.applyInventoryUpdate(nil, results)

	// Disconnected twice: the second call replaces the timer. The poller must
	// be attached first or disconnected() is a no-op.
	poller.connected()
	poller.disconnected()
	poller.disconnected()
	if poller.graceTimer == nil {
		t.Error("grace timer must be armed")
	}

	// Connected cancels the grace countdown.
	poller.connected()
	if poller.graceTimer != nil {
		t.Error("connected must cancel the grace timer")
	}
	if !poller.attached.Load() {
		t.Error("poller must be attached")
	}

	// Disconnect, then stop: stop() cancels the armed grace timer.
	poller.disconnected()
	poller.stop()
	select {
	case <-poller.stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not finish")
	}
	if !poller.stopped.Load() {
		t.Error("stopped flag")
	}
	// A stopped poller refuses updates.
	poller.applyInventoryUpdate(&pb.AgentInventoryUpdate{Revision: 1}, results)

	// A nil poller tolerates apply calls.
	var nilPoller *processPoller
	nilPoller.applyInventoryUpdate(&pb.AgentInventoryUpdate{}, results)
}

func TestPollerMaintenanceTick(t *testing.T) {
	orig := snmpSessionMaintenanceInterval
	snmpSessionMaintenanceInterval = 20 * time.Millisecond
	t.Cleanup(func() { snmpSessionMaintenanceInterval = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	poller := newProcessPoller(ctx, newResultQueue(8), false)
	time.Sleep(60 * time.Millisecond) // let the ticker fire at least twice
	poller.stop()
	<-poller.stopDone
}
