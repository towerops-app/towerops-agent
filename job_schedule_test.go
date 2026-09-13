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
func TestSplitRecurringJobsCoversEveryRecurringType(t *testing.T) {
	jobs := []*pb.AgentJob{
		{JobId: "discover:device-1", JobType: pb.JobType_DISCOVER},
		{JobId: "poll:device-1", JobType: pb.JobType_POLL},
		{JobId: "mikrotik:device-1", JobType: pb.JobType_MIKROTIK},
		{JobId: "ping:device-1", JobType: pb.JobType_PING},
		{JobId: "live_poll:device-1:topic", JobType: pb.JobType_POLL},
		{JobId: "probe:device-1", JobType: pb.JobType_PING},
		{JobId: "credential:test", JobType: pb.JobType_TEST_CREDENTIALS},
		{JobId: "lldp:device-1", JobType: pb.JobType_LLDP_TOPOLOGY},
		{JobId: "sweep:subnet-1", JobType: pb.JobType_NETWORK_SWEEP},
	}

	recurring, oneShot := splitRecurringJobs(jobs)
	if got := jobIDs(recurring); !slices.Equal(got, []string{
		"discover:device-1",
		"poll:device-1",
		"mikrotik:device-1",
		"ping:device-1",
	}) {
		t.Fatalf("recurring job IDs = %v", got)
	}
	if got := jobIDs(oneShot); !slices.Equal(got, []string{
		"live_poll:device-1:topic",
		"probe:device-1",
		"credential:test",
		"lldp:device-1",
		"sweep:subnet-1",
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
		testScheduleSpec("job-1", "new", time.Minute, runs),
	})
	select {
	case <-oldRun.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel old assignment")
	}
	assertNoInvocation(t, runs)
	close(oldRun.done)

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

func TestRecurringSchedulerReportsPoolBackpressure(t *testing.T) {
	clock := newManualScheduleClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notices := make(chan outbound, 1)
	pools := &jobPools{
		snmp:     newWorkerPool(1),
		mikrotik: newWorkerPool(1),
		ping:     newWorkerPool(1),
		checks:   newWorkerPool(1),
		notices:  notices,
	}
	release := make(chan struct{})
	fillWorkerPool(t, pools.snmp, release)

	scheduler := newRecurringScheduler(ctx, clock)
	scheduler.replaceJobs([]*pb.AgentJob{{
		JobId:           "poll:device-1",
		JobType:         pb.JobType_POLL,
		DeviceId:        "device-1",
		IntervalSeconds: 29,
	}}, pools, testQueue())

	select {
	case notice := <-notices:
		errorMessage := decodeAgentError(t, notice)
		if errorMessage.JobId != "poll:device-1" {
			t.Fatalf("overload notice job_id = %q", errorMessage.JobId)
		}
	case <-time.After(time.Second):
		t.Fatal("rejected scheduled tick did not emit overload notice")
	}
	if timer := nextManualTimer(t, clock); timer.interval != 29*time.Second {
		t.Fatalf("job timer interval = %s, want 29s", timer.interval)
	}

	scheduler.cancelAll()
	close(release)
	pools.snmp.stop()
	pools.mikrotik.stop()
	pools.ping.stop()
	pools.checks.stop()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
	}
}

func TestRecurringSchedulerUsesCheckInterval(t *testing.T) {
	clock := newManualScheduleClock()
	notices := make(chan outbound, 1)
	pools := &jobPools{checks: newWorkerPool(1), notices: notices}
	release := make(chan struct{})
	fillWorkerPool(t, pools.checks, release)

	scheduler := newRecurringScheduler(context.Background(), clock)
	scheduler.replaceChecks([]*pb.Check{{
		Id:              "check-1",
		IntervalSeconds: 47,
	}}, pools, testQueue())

	select {
	case notice := <-notices:
		errorMessage := decodeAgentError(t, notice)
		if errorMessage.JobId != "check-1" {
			t.Fatalf("overload notice job_id = %q", errorMessage.JobId)
		}
	case <-time.After(time.Second):
		t.Fatal("rejected scheduled check did not emit overload notice")
	}
	if timer := nextManualTimer(t, clock); timer.interval != 47*time.Second {
		t.Fatalf("check timer interval = %s, want 47s", timer.interval)
	}

	scheduler.cancelAll()
	close(release)
	pools.checks.stop()
	if !scheduler.wait(time.Second) {
		t.Fatal("scheduler did not stop")
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

func decodeAgentError(t *testing.T, notice outbound) *pb.AgentError {
	t.Helper()
	if notice.event != "error" {
		t.Fatalf("notice event = %q, want error", notice.event)
	}
	var message pb.AgentError
	if !decodeBinaryPayload("error", notice.payload, &message) {
		t.Fatal("decode overload notice")
	}
	return &message
}
