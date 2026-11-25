// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

const legacyJobInterval = 60 * time.Second

// maxFirstTickDelay bounds the stagger applied by the legacy (time-free
// clock) first-tick path. Clocks that report wall time use
// wallClockPhaseDelay instead, which spreads across the whole interval and
// survives reconnects (finding B3).
const maxFirstTickDelay = 60 * time.Second

// immediateChangeSlots is how many in-place assignment changes may skip the
// phase and run immediately (finding B4). Any single change on a small
// inventory is immediate; on larger inventories the limit is 5% of the
// group, so fleet-wide pushes keep every job's existing wall-clock phase
// instead of aligning the fleet on one instant.
func immediateChangeSlots(inventorySize int) int {
	return max(1, inventorySize/20)
}

type scheduleTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type scheduleClock interface {
	NewTimer(time.Duration) scheduleTimer
}

// scheduleNowClock is implemented by clocks that can report the current
// wall time. Scheduling uses it for wall-clock phases; clocks without it
// (deterministic test clocks) fall back to the capped hash stagger.
type scheduleNowClock interface {
	Now() time.Time
}

type realScheduleClock struct{}

func (realScheduleClock) NewTimer(interval time.Duration) scheduleTimer {
	return realScheduleTimer{Timer: time.NewTimer(interval)}
}

func (realScheduleClock) Now() time.Time { return time.Now() }

type realScheduleTimer struct {
	*time.Timer
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
	// immediate skips the first-tick stagger. Set when a small share of the
	// inventory changed in place, so an operator's fix runs now rather than
	// after a delay; a fleet-wide change keeps the phase instead. The entry
	// goroutine clears it after the first tick.
	immediate bool
	// stagedImmediate is the immutable admission-time value of immediate,
	// readable by tests and diagnostics without racing the run loop.
	stagedImmediate bool
}

// recurringScheduler owns the credential-bearing assignment inventory for one
// authenticated WebSocket session. Nothing is persisted across reconnects.
// Tick lag and skipped (overlapping) ticks are recorded into processMetrics,
// not per-scheduler counters, so the heartbeat snapshot covers every
// session uniformly.
type recurringScheduler struct {
	ctx    context.Context
	cancel context.CancelFunc
	clock  scheduleClock

	// paused stops new ticks and inventory changes without cancelling
	// running ticks; set by the self-update drain, never cleared.
	paused atomic.Bool

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

// now reports the scheduling clock's wall time, or the real clock when the
// configured clock cannot provide one (deterministic test clocks).
func (s *recurringScheduler) now() time.Time {
	if clock, ok := s.clock.(scheduleNowClock); ok {
		return clock.Now()
	}
	return time.Now()
}

// wallClock reports whether the clock carries wall time, so phases and lag
// are computed against planned instants instead of the capped legacy stagger.
func (s *recurringScheduler) wallClock() bool {
	_, ok := s.clock.(scheduleNowClock)
	return ok
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

// applyJobDelta applies the job side of an incremental inventory update,
// touching only the ids the update names.
func (s *recurringScheduler) applyJobDelta(
	jobs []*pb.AgentJob,
	removes map[string]struct{},
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
	s.applyDelta(&s.jobs, specs, removes)
}

// applyCheckDelta applies the check side of an incremental inventory update,
// touching only the ids the update names.
func (s *recurringScheduler) applyCheckDelta(
	checks []*pb.Check,
	removes map[string]struct{},
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
	s.applyDelta(&s.checks, specs, removes)
}

func interval(seconds uint32) time.Duration {
	if seconds == 0 {
		return legacyJobInterval
	}
	return time.Duration(seconds) * time.Second
}

// payloadFingerprint returns the SHA-256 of the deterministically marshalled
// payload so replace can detect unchanged assignments without retaining a
// serialized copy — and its SNMP credentials — per schedule entry (finding
// B8). A nil result marks an unmarshalable payload, which is treated as
// always changed. It is a var so tests can count invocations.
var payloadFingerprint = func(payload proto.Message) []byte {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// specMatches reports whether a scheduled entry already runs the given spec:
// same interval and either the same payload pointer (unchanged assignments
// keep their decoded message across updates) or the same fingerprint.
func specMatches(current *scheduleEntry, spec scheduleSpec, fingerprint []byte) bool {
	if current == nil || current.spec.interval != spec.interval {
		return false
	}
	if current.spec.payload == spec.payload {
		return true
	}
	return fingerprint != nil && bytes.Equal(current.fingerprint, fingerprint)
}

// admitLocked swaps one changed spec into a group: the displaced entry is
// cancelled and chains its completion barrier, and the replacement starts
// with the staged immediate flag. Called with s.mu held.
func (s *recurringScheduler) admitLocked(
	group *map[string]*scheduleEntry,
	retiring map[string]<-chan struct{},
	spec scheduleSpec,
	fingerprint []byte,
	immediate bool,
) {
	current := (*group)[spec.id]
	predecessor := retiring[spec.id]
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
		immediate:   immediate && current != nil,
	}
	entry.stagedImmediate = entry.immediate
	(*group)[spec.id] = entry
	s.wg.Add(1)
	go s.run(ctx, entry)
}

// removeLocked retires one entry that is absent from the next inventory.
// Called with s.mu held.
func (s *recurringScheduler) removeLocked(
	group *map[string]*scheduleEntry,
	retiring map[string]<-chan struct{},
	id string,
) {
	current := (*group)[id]
	if current == nil {
		return
	}
	current.cancel()
	var barrier <-chan struct{} = current.stopped
	if current.predecessor != nil {
		barrier = current.predecessor
	}
	s.retire(retiring, id, barrier)
	delete(*group, id)
}

func (s *recurringScheduler) replace(group *map[string]*scheduleEntry, specs []scheduleSpec) {
	next := make(map[string]scheduleSpec, len(specs))
	for _, spec := range specs {
		next[spec.id] = spec
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.paused.Load() {
		return
	}
	retiring := s.retiringChecks
	if group == &s.jobs {
		retiring = s.retiringJobs
	}

	// Fingerprint each payload once; both passes below reuse the map.
	fingerprints := make(map[string][]byte, len(next))
	for id, spec := range next {
		current := (*group)[id]
		if current != nil && current.spec.interval == spec.interval &&
			current.spec.payload == spec.payload {
			continue
		}
		fingerprints[id] = payloadFingerprint(spec.payload)
	}

	// Count in-place changes before touching the maps: a fleet-wide push
	// (more than immediateChangeSlots of the group) must not run everything
	// immediately and align the fleet (finding B4).
	inventorySize := max(len(*group), len(next))
	changed := 0
	for id, spec := range next {
		if specMatches((*group)[id], spec, fingerprints[id]) {
			continue
		}
		changed++
	}
	immediate := changed > 0 && changed <= immediateChangeSlots(inventorySize)

	for id := range *group {
		if _, ok := next[id]; !ok {
			s.removeLocked(group, retiring, id)
		}
	}

	for id, spec := range next {
		fingerprint, computed := fingerprints[id]
		if !computed {
			continue
		}
		if specMatches((*group)[id], spec, fingerprint) {
			continue
		}
		s.admitLocked(group, retiring, spec, fingerprint, immediate)
	}
}

// applyDelta folds an incremental inventory update into one group: only the
// entries named by upserts or removes are fingerprinted or swapped, so a one
// job delta on a large fleet does not marshal and hash the whole inventory.
// A remove naming an id that is also upserted is ignored; the upsert wins.
func (s *recurringScheduler) applyDelta(
	group *map[string]*scheduleEntry,
	upserts []scheduleSpec,
	removes map[string]struct{},
) {
	type deltaChange struct {
		spec        scheduleSpec
		fingerprint []byte
	}
	changes := make([]deltaChange, 0, len(upserts))
	// Last upsert wins on a duplicate id, matching replace's next map.
	named := make(map[string]scheduleSpec, len(upserts))
	for _, spec := range upserts {
		named[spec.id] = spec
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.paused.Load() {
		return
	}
	retiring := s.retiringChecks
	if group == &s.jobs {
		retiring = s.retiringJobs
	}

	nextSize := len(*group)
	for id, spec := range named {
		delete(removes, spec.id)
		current := (*group)[id]
		if current == nil {
			nextSize++
		} else if current.spec.interval == spec.interval && current.spec.payload == spec.payload {
			continue
		}
		fingerprint := payloadFingerprint(spec.payload)
		if specMatches(current, spec, fingerprint) {
			continue
		}
		changes = append(changes, deltaChange{spec, fingerprint})
	}
	for id := range removes {
		if (*group)[id] != nil {
			nextSize--
		}
		s.removeLocked(group, retiring, id)
	}

	inventorySize := max(len(*group), nextSize)
	immediate := len(changes) > 0 && len(changes) <= immediateChangeSlots(inventorySize)
	for _, change := range changes {
		s.admitLocked(group, retiring, change.spec, change.fingerprint, immediate)
	}
}

// counts reports the live group sizes for concurrency sizing and footprint
// telemetry after a delta update.
func (s *recurringScheduler) counts() (jobs, checks int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobs), len(s.checks)
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

// activeTick tracks one running tick so the scheduler can skip overlapping
// ticks (finding D3) and so a cancelled entry still waits for the executor
// before closing its replacement barrier.
type activeTick struct {
	finished chan struct{}
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

	spec := entry.spec
	phaseInterval := spec.interval
	if phaseInterval <= 0 {
		phaseInterval = legacyJobInterval
	}

	// New entries land on their wall-clock phase hash(id) mod interval, so
	// the spread covers the whole interval and survives reconnects (B3).
	// A changed assignment on a small change runs immediately; everything
	// else keeps its phase. Test clocks without wall time keep the capped
	// legacy stagger.
	wall := s.wallClock()
	var planned time.Time
	var delay time.Duration
	if !entry.immediate {
		if wall {
			planned = s.now()
			delay = wallClockPhaseDelay(spec.id, phaseInterval, planned)
			planned = planned.Add(delay)
		} else {
			delay = firstTickDelay(spec.id, phaseInterval)
		}
	} else if wall {
		planned = s.now()
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
	entry.immediate = false

	var active *activeTick
	// The first tick starts as soon as its phase/stagger delay ends. Later
	// phase instants wait for the interval grid and skip while the previous
	// tick is still active.
	startTick := func() {
		tickPlanned := planned
		tick := &activeTick{finished: make(chan struct{})}
		go func() {
			defer close(tick.finished)
			s.runTick(ctx, spec, wall, tickPlanned)
		}()
		active = tick
	}
	startTick()
	if wall {
		planned = planned.Add(phaseInterval)
	}

	for {
		// A paused scheduler starts no tick; the entry parks until cancelAll,
		// but a tick already running still finishes and delivers its result.
		if s.paused.Load() {
			if active != nil {
				<-active.finished
			}
			<-ctx.Done()
			return
		}

		var timer scheduleTimer
		if wall {
			wait := planned.Sub(s.now())
			if wait < 0 {
				wait = 0
			}
			timer = s.clock.NewTimer(wait)
		} else {
			timer = s.clock.NewTimer(phaseInterval)
		}
		// Hold the phase instant until the timer fires, but drop the active
		// marker as soon as the running tick finishes so the next phase runs
		// again instead of being skipped forever.
		var finished <-chan struct{}
		if active != nil {
			finished = active.finished
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			if active != nil {
				<-active.finished
			}
			return
		case <-finished:
			// Clearing the active marker only permits the already scheduled
			// phase to run; it must not start a new tick before that timer
			// fires.
			timer.Stop()
			active = nil
			continue
		case <-timer.C():
			timer.Stop()
		}

		if active != nil {
			// The previous tick is still executing or waiting for pool
			// capacity: skip this phase rather than silently stretching the
			// interval (D3), and keep counting.
			processMetrics.skippedTicks.Add(1)
			if wall {
				planned = planned.Add(phaseInterval)
			}
		} else {
			startTick()
			if wall {
				planned = planned.Add(phaseInterval)
			}
		}
	}
}

// runTick starts one execution asynchronously and waits for it to complete.
// Lag is the actual start minus the planned phase instant; a zero planned
// instant (legacy test clocks) records nothing. A rejected submission is a
// completed tick: the scheduler retries on the next phase.
func (s *recurringScheduler) runTick(ctx context.Context, spec scheduleSpec, wall bool, planned time.Time) {
	if wall && !planned.IsZero() {
		processMetrics.recordScheduleLag(s.now().Sub(planned))
	}
	done := make(chan struct{})
	accepted := spec.submit(ctx, func() { close(done) })
	if !accepted {
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
		// Replacement and disconnect cancel the executor. Wait until it has
		// released the assignment before the entry barrier closes.
		<-done
	}
}

// firstTickDelay returns the deterministic offset in
// [0, min(interval, maxFirstTickDelay)) used by clocks that cannot report
// wall time. Production scheduling instead uses wallClockPhaseDelay, whose
// spread covers the whole interval and survives reconnects.
func firstTickDelay(id string, interval time.Duration) time.Duration {
	window := min(interval, maxFirstTickDelay)
	if window <= 0 {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(id))
	return time.Duration(hash.Sum64() % uint64(window))
}

// schedulePhase returns the deterministic offset hash(id) mod interval that
// fixes an assignment's position within its interval.
func schedulePhase(id string, interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(id))
	return time.Duration(hash.Sum64() % uint64(interval))
}

// wallClockPhaseDelay returns the delay from now until the next instant t
// where (t - hash(id)) mod interval == 0. Because the phase is derived from
// the stable job ID and wall time, entries land on the same schedule across
// reconnects, inventory pushes and restarts (findings B3/D3).
func wallClockPhaseDelay(id string, interval time.Duration, now time.Time) time.Duration {
	if interval <= 0 {
		return 0
	}
	phase := int64(schedulePhase(id, interval))
	elapsed := now.UnixNano() % int64(interval)
	return time.Duration((phase - elapsed + int64(interval)) % int64(interval))
}

// runOnce is the legacy single-tick primitive: it submits, then holds until
// both the interval elapsed and the task completed. The phase loop in run
// supersedes it for live scheduling; it is retained for callers that want
// one serialized tick.
func (s *recurringScheduler) runOnce(ctx context.Context, spec scheduleSpec) bool {
	// A paused scheduler starts no tick; the entry parks until cancelAll.
	if s.paused.Load() {
		<-ctx.Done()
		return false
	}
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

// pause stops every entry from starting another tick and refuses inventory
// replacement. Unlike cancelAll it leaves entry contexts live, so a tick
// already running finishes and delivers its result. Session stop still calls
// cancelAll to end the parked entries.
func (s *recurringScheduler) pause() {
	s.paused.Store(true)
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
