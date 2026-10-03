// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

const legacyJobInterval = 60 * time.Second

// maxFirstTickDelay bounds the stagger applied to an entry's first tick. The
// scheduler is rebuilt every session, so an offset measured in whole intervals
// would postpone long-interval jobs past the next reconnect indefinitely.
const maxFirstTickDelay = 60 * time.Second

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
	cancel      context.CancelFunc
	stopped     chan struct{}
	predecessor <-chan struct{}
	spec        scheduleSpec
	fingerprint []byte
	// immediate skips the first-tick stagger. Set when an existing assignment
	// changed in place, so an operator's fix runs now rather than after a delay.
	immediate bool
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
	// Retiring inventories retain only completion barriers, never payloads.
	retiringJobs   map[string]<-chan struct{}
	retiringChecks map[string]<-chan struct{}
	wg             sync.WaitGroup
}

func newRecurringScheduler(ctx context.Context, clock scheduleClock) *recurringScheduler {
	schedulerCtx, cancel := context.WithCancel(ctx)
	return &recurringScheduler{
		ctx:            schedulerCtx,
		cancel:         cancel,
		clock:          clock,
		jobs:           make(map[string]*scheduleEntry),
		checks:         make(map[string]*scheduleEntry),
		retiringJobs:   make(map[string]<-chan struct{}),
		retiringChecks: make(map[string]<-chan struct{}),
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
		specs = append(specs, scheduleSpec{
			id:       job.JobId,
			interval: interval(job.IntervalSeconds),
			payload:  job,
			submit: func(ctx context.Context, done func()) bool {
				return submitJob(ctx, job, pools, out, done, true)
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
		specs = append(specs, scheduleSpec{
			id:       check.Id,
			interval: interval(check.IntervalSeconds),
			payload:  check,
			submit: func(ctx context.Context, done func()) bool {
				return submitCheck(ctx, check, pools, out, done, true)
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

// payloadFingerprint marshals the payload once so replace can detect unchanged
// assignments without a protobuf reflection walk on every inbound frame. A nil
// result marks an unmarshalable payload, which is treated as always changed.
func payloadFingerprint(payload proto.Message) []byte {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil
	}
	return data
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
	retiring := s.retiringChecks
	if group == &s.jobs {
		retiring = s.retiringJobs
	}

	for id, current := range *group {
		if _, ok := next[id]; !ok {
			current.cancel()
			var barrier <-chan struct{} = current.stopped
			if current.predecessor != nil {
				barrier = current.predecessor
			}
			s.retire(retiring, id, barrier)
			delete(*group, id)
		}
	}

	for id, spec := range next {
		current := (*group)[id]
		fingerprint := payloadFingerprint(spec.payload)
		if current != nil && current.spec.interval == spec.interval &&
			fingerprint != nil && bytes.Equal(current.fingerprint, fingerprint) {
			continue
		}

		predecessor := retiring[id]
		if current != nil {
			current.cancel()
			if current.predecessor != nil {
				predecessor = current.predecessor
			} else {
				predecessor = current.stopped
			}
		}

		ctx, cancel := context.WithCancel(s.ctx)
		entry := &scheduleEntry{
			cancel:      cancel,
			stopped:     make(chan struct{}),
			predecessor: predecessor,
			spec:        spec,
			fingerprint: fingerprint,
			immediate:   current != nil,
		}
		(*group)[id] = entry
		s.wg.Add(1)
		go s.run(ctx, entry)
	}
}

// retire is called with s.mu held. A waiting replacement can stop before
// its executor predecessor, so retain the executor's barrier in that case.
func (s *recurringScheduler) retire(retiring map[string]<-chan struct{}, id string, barrier <-chan struct{}) {
	if retiring[id] == barrier {
		return
	}
	retiring[id] = barrier
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-barrier
		s.mu.Lock()
		if retiring[id] == barrier {
			delete(retiring, id)
		}
		s.mu.Unlock()
	}()
}

func (s *recurringScheduler) run(ctx context.Context, entry *scheduleEntry) {
	defer s.wg.Done()
	defer close(entry.stopped)

	if entry.predecessor != nil {
		select {
		case <-ctx.Done():
			return
		case <-entry.predecessor:
		}
		s.mu.Lock()
		entry.predecessor = nil
		s.mu.Unlock()
	}

	// Only new entries are staggered; a changed assignment runs as soon as its
	// predecessor has released the ID.
	var delay time.Duration
	if !entry.immediate {
		delay = firstTickDelay(entry.spec.id, entry.spec.interval)
	}
	if delay > 0 {
		timer := s.clock.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
	}

	for {
		if !s.runOnce(ctx, entry.spec) {
			return
		}
	}
}

// firstTickDelay returns the deterministic offset in
// [0, min(interval, maxFirstTickDelay)) that staggers a new entry's first tick.
// Reconnects replay the whole assignment inventory at once, so spreading first
// ticks by a hash of the stable job ID avoids a synchronized burst into bounded
// worker-pool queues. The window is capped because entries restart on every
// reconnect: an uncapped hourly offset of 40 minutes would never fire on an
// agent that reconnects every 30 minutes.
func firstTickDelay(id string, interval time.Duration) time.Duration {
	window := min(interval, maxFirstTickDelay)
	if window <= 0 {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(id))
	return time.Duration(hash.Sum64() % uint64(window))
}

// runOnce starts one tick promptly, then holds the next tick until both the
// configured interval has elapsed and the task has completed. The interval
// timer starts before submission because submission waits for bounded
// worker-pool capacity; measuring the period from dispatch keeps the
// configured cadence instead of adding queue-wait time to every cycle.
func (s *recurringScheduler) runOnce(ctx context.Context, spec scheduleSpec) bool {
	done := make(chan struct{})
	timer := s.clock.NewTimer(spec.interval)
	defer timer.Stop()
	accepted := spec.submit(ctx, func() { close(done) })

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
	clear(s.retiringJobs)
	clear(s.retiringChecks)
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
