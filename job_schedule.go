// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

const legacyJobInterval = 60 * time.Second

type scheduleTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type scheduleClock interface {
	NewTimer(time.Duration) scheduleTimer
}

type realScheduleClock struct{}

type realScheduleTimer struct {
	*time.Timer
}

func (realScheduleClock) NewTimer(interval time.Duration) scheduleTimer {
	return realScheduleTimer{Timer: time.NewTimer(interval)}
}

func (t realScheduleTimer) C() <-chan time.Time {
	return t.Timer.C
}

type scheduleSpec struct {
	id       string
	interval time.Duration
	payload  proto.Message
	submit   func(context.Context, func()) bool
}

type scheduleEntry struct {
	cancel  context.CancelFunc
	stopped chan struct{}
	spec    scheduleSpec
}

// recurringScheduler owns the credential-bearing assignment inventory for one
// authenticated WebSocket session. Nothing is persisted across reconnects.
type recurringScheduler struct {
	ctx    context.Context
	cancel context.CancelFunc
	clock  scheduleClock

	mu     sync.Mutex
	closed bool
	jobs   map[string]*scheduleEntry
	checks map[string]*scheduleEntry
	wg     sync.WaitGroup
}

func newRecurringScheduler(ctx context.Context, clock scheduleClock) *recurringScheduler {
	schedulerCtx, cancel := context.WithCancel(ctx)
	return &recurringScheduler{
		ctx:    schedulerCtx,
		cancel: cancel,
		clock:  clock,
		jobs:   make(map[string]*scheduleEntry),
		checks: make(map[string]*scheduleEntry),
	}
}

func (s *recurringScheduler) replaceJobs(
	jobs []*pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
) {
	specs := make([]scheduleSpec, 0, len(jobs))
	for _, job := range jobs {
		if job == nil || job.JobId == "" {
			slog.Error("recurring job dropped, stable job ID is required")
			continue
		}
		job := proto.Clone(job).(*pb.AgentJob)
		specs = append(specs, scheduleSpec{
			id:       job.JobId,
			interval: interval(job.IntervalSeconds),
			payload:  job,
			submit: func(ctx context.Context, done func()) bool {
				return submitJob(ctx, job, pools, out, done)
			},
		})
	}
	s.replace(&s.jobs, specs)
}

func (s *recurringScheduler) replaceChecks(
	checks []*pb.Check,
	pools *jobPools,
	out *resultQueue,
) {
	specs := make([]scheduleSpec, 0, len(checks))
	for _, check := range checks {
		if check == nil || check.Id == "" {
			slog.Error("recurring check dropped, stable check ID is required")
			continue
		}
		check := proto.Clone(check).(*pb.Check)
		specs = append(specs, scheduleSpec{
			id:       check.Id,
			interval: interval(check.IntervalSeconds),
			payload:  check,
			submit: func(ctx context.Context, done func()) bool {
				return submitCheck(ctx, check, pools, out, done)
			},
		})
	}
	s.replace(&s.checks, specs)
}

func interval(seconds uint32) time.Duration {
	if seconds == 0 {
		return legacyJobInterval
	}
	return time.Duration(seconds) * time.Second
}

func (s *recurringScheduler) replace(group *map[string]*scheduleEntry, specs []scheduleSpec) {
	next := make(map[string]scheduleSpec, len(specs))
	for _, spec := range specs {
		next[spec.id] = spec
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	for id, current := range *group {
		if _, ok := next[id]; !ok {
			current.cancel()
			delete(*group, id)
		}
	}

	for id, spec := range next {
		current := (*group)[id]
		if current != nil && current.spec.interval == spec.interval && proto.Equal(current.spec.payload, spec.payload) {
			continue
		}

		var predecessor <-chan struct{}
		if current != nil {
			current.cancel()
			predecessor = current.stopped
		}

		ctx, cancel := context.WithCancel(s.ctx)
		entry := &scheduleEntry{cancel: cancel, stopped: make(chan struct{}), spec: spec}
		(*group)[id] = entry
		s.wg.Add(1)
		go s.run(ctx, entry, predecessor)
	}
}

func (s *recurringScheduler) run(
	ctx context.Context,
	entry *scheduleEntry,
	predecessor <-chan struct{},
) {
	defer s.wg.Done()
	defer close(entry.stopped)

	if predecessor != nil {
		select {
		case <-predecessor:
		case <-ctx.Done():
			<-predecessor
			return
		}
	}

	for {
		if !s.runOnce(ctx, entry.spec) {
			return
		}
	}
}

// runOnce starts one tick promptly, then holds the next tick until both the
// configured interval has elapsed and the accepted task has completed. A full
// worker pool is reported by submit and retried only at the next interval.
func (s *recurringScheduler) runOnce(ctx context.Context, spec scheduleSpec) bool {
	done := make(chan struct{})
	accepted := spec.submit(ctx, func() { close(done) })
	timer := s.clock.NewTimer(spec.interval)
	defer timer.Stop()

	if !accepted {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C():
			return true
		}
	}

	completed := false
	elapsed := false
	for !completed || !elapsed {
		select {
		case <-ctx.Done():
			// Replacement and disconnect cancel the executor. Wait until it has
			// released the assignment before a replacement with the same ID runs.
			if !completed {
				<-done
			}
			return false
		case <-done:
			completed = true
			done = nil
		case <-timer.C():
			elapsed = true
		}
	}
	return true
}

func (s *recurringScheduler) cancelAll() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for _, entry := range s.jobs {
		entry.cancel()
	}
	for _, entry := range s.checks {
		entry.cancel()
	}
	clear(s.jobs)
	clear(s.checks)
	s.cancel()
	s.mu.Unlock()
}

func (s *recurringScheduler) wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
