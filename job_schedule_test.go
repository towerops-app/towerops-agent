// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

type manualScheduleClock struct {
	requests chan manualTimerRequest
}

type manualTimerRequest struct {
	interval time.Duration
	timer    *manualScheduleTimer
}

type manualScheduleTimer struct {
	ch chan time.Time
}

func newManualScheduleClock() *manualScheduleClock {
	return &manualScheduleClock{requests: make(chan manualTimerRequest, 32)}
}

func (c *manualScheduleClock) NewTimer(interval time.Duration) scheduleTimer {
	timer := &manualScheduleTimer{ch: make(chan time.Time)}
	c.requests <- manualTimerRequest{interval: interval, timer: timer}
	return timer
}

func (t *manualScheduleTimer) C() <-chan time.Time { return t.ch }
func (t *manualScheduleTimer) Stop() bool          { return true }

type scheduleInvocation struct {
	ctx  context.Context
	done chan struct{}
}

func nextInvocation(t *testing.T, runs <-chan scheduleInvocation) scheduleInvocation {
	t.Helper()
	select {
	case run := <-runs:
		return run
	case <-time.After(time.Second):
		t.Fatal("scheduler did not submit work")
		return scheduleInvocation{}
	}
}

func nextManualTimer(t *testing.T, clock *manualScheduleClock) manualTimerRequest {
	t.Helper()
	select {
	case request := <-clock.requests:
		return request
	case <-time.After(time.Second):
		t.Fatal("scheduler did not create timer")
		return manualTimerRequest{}
	}
}

func fireManualTimer(t *testing.T, timer *manualScheduleTimer) {
	t.Helper()
	select {
	case timer.ch <- time.Time{}:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not receive timer tick")
	}
}

func assertNoInvocation(t *testing.T, runs <-chan scheduleInvocation) {
	t.Helper()
	select {
	case <-runs:
		t.Fatal("scheduler submitted overlapping or unchanged work")
	default:
	}
}

func testScheduleSpec(id, value string, interval time.Duration, runs chan<- scheduleInvocation) scheduleSpec {
	return scheduleSpec{
		id:       id,
		interval: interval,
		payload:  &pb.Check{Id: id, CheckType: value},
		submit: func(ctx context.Context, done func()) bool {
			if ctx.Err() != nil {
				return false
			}
			completion := make(chan struct{})
			runs <- scheduleInvocation{ctx: ctx, done: completion}
			go func() {
				select {
				case <-completion:
					done()
				case <-ctx.Done():
					<-completion

					done()
				}
			}()
			return true
		},
	}
}
func TestSplitRecurringJobsUsesIntervalSignal(t *testing.T) {
	jobs := []*pb.AgentJob{
		{JobId: "discover:device-1", JobType: pb.JobType_DISCOVER, IntervalSeconds: 60},
		{JobId: "poll:device-1", JobType: pb.JobType_POLL, IntervalSeconds: 60},
		{JobId: "mikrotik:device-1", JobType: pb.JobType_MIKROTIK, IntervalSeconds: 60},
		{JobId: "ping:device-1", JobType: pb.JobType_PING, IntervalSeconds: 60},
		{JobId: "future:device-1", JobType: pb.JobType_NETWORK_SWEEP, IntervalSeconds: 60},
		{JobId: "poll-with-new-prefix", JobType: pb.JobType_POLL},
		{JobId: "credential:test", JobType: pb.JobType_TEST_CREDENTIALS},
		nil,
	}

	recurring, oneShot := splitRecurringJobs(jobs)
	if got := jobIDs(recurring); !slices.Equal(got, []string{
		"discover:device-1",
		"poll:device-1",
		"mikrotik:device-1",
		"ping:device-1",
		"future:device-1",
	}) {
		t.Fatalf("recurring job IDs = %v", got)
	}
	if got := jobIDs(oneShot); !slices.Equal(got, []string{
		"poll-with-new-prefix",
		"credential:test",
	}) {
		t.Fatalf("one-shot job IDs = %v", got)
	}
}

func jobIDs(jobs []*pb.AgentJob) []string {
	ids := make([]string, len(jobs))
	for i, job := range jobs {
		ids[i] = job.JobId
	}
	return ids
}

func TestRecurringSchedulerRejectsInvalidAndPostDisconnectAssignments(t *testing.T) {
	scheduler := newRecurringScheduler(context.Background(), newManualScheduleClock())
	scheduler.replaceJobs([]*pb.AgentJob{
		nil,
		{JobType: pb.JobType_POLL},
	}, nil, nil)
	scheduler.replaceChecks([]*pb.Check{
		nil,
		{CheckType: "http"},
	}, nil, nil)
	if len(scheduler.jobs) != 0 || len(scheduler.checks) != 0 {
		t.Fatal("scheduler retained assignment without a stable ID")
	}

	scheduler.cancelAll()
	scheduler.replaceJobs([]*pb.AgentJob{{
		JobId:   "poll:device-1",
		JobType: pb.JobType_POLL,
	}}, nil, nil)
	if len(scheduler.jobs) != 0 {
		t.Fatal("disconnected scheduler accepted a new assignment")
	}
	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerIntervalAndNonOverlap(t *testing.T) {
	clock := newManualScheduleClock()
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan scheduleInvocation, 4)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "first", 17*time.Second, runs),
	})
	first := nextInvocation(t, runs)
	timer := nextManualTimer(t, clock)
	if timer.interval != 17*time.Second {
		t.Fatalf("timer interval = %s, want 17s", timer.interval)
	}

	fireManualTimer(t, timer.timer)
	assertNoInvocation(t, runs)
	close(first.done)

	second := nextInvocation(t, runs)
	close(second.done)
	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerReplacementAndRemoval(t *testing.T) {
	clock := newManualScheduleClock()
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan scheduleInvocation, 4)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "old", time.Minute, runs),
	})
	oldRun := nextInvocation(t, runs)
	_ = nextManualTimer(t, clock)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "intermediate", time.Minute, runs),
	})
	intermediate := scheduler.jobs["job-1"]
	select {
	case <-oldRun.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel old assignment")
	}
	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "new", time.Minute, runs),
	})
	assertNoInvocation(t, runs)
	close(oldRun.done)
	select {
	case <-intermediate.stopped:
	case <-time.After(time.Second):
		t.Fatal("superseded replacement did not stop")
	}

	newRun := nextInvocation(t, runs)
	_ = nextManualTimer(t, clock)
	entry := scheduler.jobs["job-1"]
	scheduler.replace(&scheduler.jobs, nil)
	select {
	case <-newRun.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("removal did not cancel assignment")
	}
	close(newRun.done)
	select {
	case <-entry.stopped:
	case <-time.After(time.Second):
		t.Fatal("removed assignment did not stop")
	}
	assertNoInvocation(t, runs)

	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerPreservesUnchangedAssignment(t *testing.T) {
	clock := newManualScheduleClock()
	scheduler := newRecurringScheduler(context.Background(), clock)
	runs := make(chan scheduleInvocation, 4)
	spec := testScheduleSpec("job-1", "same", time.Minute, runs)

	scheduler.replace(&scheduler.jobs, []scheduleSpec{spec})
	first := nextInvocation(t, runs)
	timer := nextManualTimer(t, clock)
	entry := scheduler.jobs["job-1"]

	scheduler.replace(&scheduler.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "same", time.Minute, runs),
	})
	if scheduler.jobs["job-1"] != entry {
		t.Fatal("unchanged assignment was replaced")
	}
	assertNoInvocation(t, runs)

	close(first.done)
	fireManualTimer(t, timer.timer)
	second := nextInvocation(t, runs)
	close(second.done)
	scheduler.cancelAll()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerReconnectStartsEmpty(t *testing.T) {
	clock := newManualScheduleClock()
	firstSession := newRecurringScheduler(context.Background(), clock)
	runs := make(chan scheduleInvocation, 4)
	firstSession.replace(&firstSession.jobs, []scheduleSpec{
		testScheduleSpec("job-1", "credential-bearing", time.Minute, runs),
	})
	run := nextInvocation(t, runs)
	_ = nextManualTimer(t, clock)

	firstSession.cancelAll()
	select {
	case <-run.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel assignment")
	}
	close(run.done)
	if !firstSession.wait(time.Second) {
		t.Fatal("disconnected scheduler did not stop")
	}
	if len(firstSession.jobs) != 0 || len(firstSession.checks) != 0 {
		t.Fatal("disconnected scheduler retained assignment inventory")
	}

	secondSession := newRecurringScheduler(context.Background(), newManualScheduleClock())
	assertNoInvocation(t, runs)
	secondSession.cancelAll()
	if !secondSession.wait(time.Second) {
		t.Fatal("replacement session scheduler did not stop")
	}
}

func TestRecurringSchedulerWaitsForPoolCapacity(t *testing.T) {
	clock := newManualScheduleClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newWorkerPool(1)
	release := make(chan struct{})
	fillWorkerPool(t, pool, release)

	started := make(chan struct{})
	scheduler := newRecurringScheduler(ctx, clock)
	scheduler.replace(&scheduler.jobs, []scheduleSpec{{
		id:       "job-1",
		interval: 29 * time.Second,
		payload:  &pb.AgentJob{JobId: "job-1"},
		submit: func(ctx context.Context, done func()) bool {
			return pool.submitWait(ctx, func() {
				close(started)
				done()
			})
		},
	}})

	select {
	case <-started:
		t.Fatal("scheduled task bypassed full queue")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-clock.requests:
		t.Fatal("scheduler started its interval before queue admission")
	default:
	}

	close(release)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled task did not start after capacity opened")
	}
	if timer := nextManualTimer(t, clock); timer.interval != 29*time.Second {
		t.Fatalf("job timer interval = %s, want 29s", timer.interval)
	}

	scheduler.cancelAll()
	pool.stop()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerUsesCheckInterval(t *testing.T) {
	clock := newManualScheduleClock()
	pools := &jobPools{checks: newWorkerPool(1), notices: make(chan outbound, 1)}
	scheduler := newRecurringScheduler(context.Background(), clock)
	scheduler.replaceChecks([]*pb.Check{{
		Id:              "check-1",
		IntervalSeconds: 47,
	}}, pools, testQueue())

	if timer := nextManualTimer(t, clock); timer.interval != 47*time.Second {
		t.Fatalf("check timer interval = %s, want 47s", timer.interval)
	}

	scheduler.cancelAll()
	pools.checks.stop()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerRetriesAfterRejectedSubmission(t *testing.T) {
	clock := newManualScheduleClock()
	scheduler := newRecurringScheduler(context.Background(), clock)
	continued := make(chan bool, 1)
	go func() {
		continued <- scheduler.runOnce(context.Background(), scheduleSpec{
			interval: time.Hour,
			submit: func(context.Context, func()) bool {
				return false
			},
		})
	}()

	timer := nextManualTimer(t, clock)
	fireManualTimer(t, timer.timer)
	if !<-continued {
		t.Fatal("scheduler stopped after its worker pool rejected one submission")
	}
}

func TestRecurringSchedulerRejectedSubmissionStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scheduler := newRecurringScheduler(context.Background(), realScheduleClock{})
	if scheduler.runOnce(ctx, scheduleSpec{
		interval: time.Hour,
		submit: func(context.Context, func()) bool {
			return false
		},
	}) {
		t.Fatal("scheduler continued after cancellation")
	}
}

func TestRecurringSchedulerWaitHonorsTimeout(t *testing.T) {
	scheduler := newRecurringScheduler(context.Background(), realScheduleClock{})
	scheduler.wg.Add(1)
	if scheduler.wait(time.Millisecond) {
		t.Fatal("scheduler wait succeeded while work was still active")
	}
	scheduler.wg.Done()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler wait did not observe completed work")
	}
}

func fillWorkerPool(t *testing.T, pool *workerPool, release <-chan struct{}) {
	t.Helper()
	started := make(chan struct{})
	if !pool.submit(context.Background(), func() { close(started); <-release }) {
		t.Fatal("worker pool rejected initial blocker")
	}
	<-started
	for range cap(pool.tasks) {
		if !pool.submit(context.Background(), func() { <-release }) {
			t.Fatal("worker pool rejected task before queue filled")
		}
	}
}
