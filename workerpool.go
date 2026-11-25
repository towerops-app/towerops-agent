// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// admissionLane says which queue quota a submission draws from. The
// distinction matters only for admission control: both lanes feed the same
// task channel and the same workers.
type admissionLane uint8

const (
	// laneOneShot is used by every non-blocking submission (one-shot jobs,
	// ad-hoc checks, dispatchGated coordinators). It may use the whole task
	// queue, including the slots reserved against recurring load.
	laneOneShot admissionLane = iota
	// laneRecurring is used by blocking scheduler submissions. It may occupy
	// at most recurringCapacity of the queue so recurring saturation can
	// never consume the reserved one-shot slots (finding A5).
	laneRecurring
)

// workerPoolStats is a point-in-time snapshot for the heartbeat's pool load
// fields. All values are advisory: each is read without coordinating with
// concurrent admissions, so a caller sees a consistent-enough sample.
type workerPoolStats struct {
	// Limit is the configured worker limit (setWorkerLimit), not the number
	// of live goroutines during a scale-down drain.
	Limit int
	// Workers is the number of worker goroutines the pool currently keeps.
	Workers int
	// Busy counts every admitted coordinator (jitter/gate wait) plus queued
	// and running tasks; the self-update drain waits for zero.
	Busy int64
	// Running counts tasks currently executing on workers.
	Running int64
	// Queued is the number of tasks waiting in the task channel.
	Queued int
	// RecurringInFlight is queued-plus-running recurring work. It can
	// exceed RecurringCapacity because the lane token frees at dequeue
	// while this count holds until the task finishes.
	RecurringInFlight int
	// RecurringCapacity is the maximum queued recurring work the lane
	// admits; the A5 reserve for one-shot jobs sits on top of it.
	RecurringCapacity int
	// OneShotReserve is the queue capacity recurring load can never occupy.
	OneShotReserve int
}

// workerPool is a goroutine pool with a dynamically resizable worker limit
// for executing tasks. Workers are started and retired on demand by
// setWorkerLimit; retiring workers drain their current task and exit, so
// in-flight work is never cancelled by a resize.
//
// Admission has two lanes sharing one task channel. Recurring scheduler
// submissions take a queue token first and may occupy at most
// recurringCapacity = cap(tasks) - oneShotReserve queue slots, so a saturated
// recurring schedule always leaves oneShotReserve queue slots for one-shot
// work (finding A5). The token frees when a worker dequeues the task, so the
// worker limit, not the lane, bounds how much recurring work runs at once.
// One-shot submissions use the whole queue but never take tokens.
type workerPool struct {
	tasks chan func()
	// dispatch bounds the one-shot coordinators parked on a busy target's
	// gate. Jitter runs on a timer and an uncontended job goes straight to
	// the queue, so neither holds a slot: admission is refused only when the
	// queue itself is full or when this many jobs are already waiting on
	// busy devices. Without the bound a large push at a stalled device would
	// park an unbounded set of goroutines outside the pool's backpressure.
	dispatch chan struct{}
	// busy counts work admitted to this pool that has not finished:
	// coordinators in jitter or gate wait, queued tasks and running tasks.
	// The self-update drain waits for it to reach zero.
	busy atomic.Int64
	// running counts tasks currently executing; stats only.
	running atomic.Int64
	// paused refuses new submissions while admitted work finishes; set by
	// the self-update drain, never cleared.
	paused atomic.Bool
	wg     sync.WaitGroup
	once   sync.Once
	mu     sync.RWMutex
	closed bool
	// workers is the live worker set; entries are removed when the worker
	// exits, so during a scale-down Workers can trail the retiring set only
	// for tasks already running (they always finish).
	workers map[*poolWorker]struct{}
	// limit is the configured worker count; mutated under mu.
	limit int
	// recurring holds one token per queued recurring task. Capacity
	// cap(tasks)-oneShotReserve keeps the reserved queue slots unreachable
	// from the recurring lane. The token frees when a worker dequeues the
	// task: the lane guards queue occupancy, not running work, so
	// setWorkerLimit can grow recurring execution past the queue size.
	recurring chan struct{}
	// recurringInFlight counts admitted recurring tasks that have not
	// finished (queued plus running), for the heartbeat load snapshot.
	recurringInFlight atomic.Int64
	// oneShotReserve is the number of queue slots held back from recurring
	// submissions; computed once from the initial pool size.
	oneShotReserve int
}

// poolWorker is one worker goroutine. retire is closed by setWorkerLimit to
// remove it after its current task finishes; stop() never closes it, so the
// drain still runs out the task channel.
type poolWorker struct {
	retire chan struct{}
}

// oneShotReserveFor returns the queue capacity recurring load cannot touch.
// The reservation is the smaller of the A5 example (10 slots per pool) and a
// tenth of the queue, never below one slot on the smallest pools.
func oneShotReserveFor(n int) int {
	queue := n * 4
	return max(1, min(10, queue/10))
}

// snmpWorkerLimit is the D1 default SNMP concurrency for an inventory of
// deviceCount devices: at least 100 workers, plus one worker per three
// devices above that. Callers override it per deployment with
// setWorkerLimit.
func snmpWorkerLimit(deviceCount int) int {
	return max(100, deviceCount/3)
}

// snmpConcurrencyLimit resolves the SNMP worker limit once the inventory is
// known: an explicit runtime flag wins; otherwise the pool grows to
// snmpWorkerLimit(deviceCount). The poller calls this from its inventory
// path and applies it with snmp.setWorkerLimit.
func snmpConcurrencyLimit(configured int, deviceCount int) int {
	if configured > 0 {
		return configured
	}
	return snmpWorkerLimit(deviceCount)
}

// newWorkerPool creates a pool with n worker goroutines.
func newWorkerPool(n int) *workerPool {
	n = max(1, n)
	p := &workerPool{
		tasks:          make(chan func(), n*4),
		dispatch:       make(chan struct{}, n*5),
		workers:        make(map[*poolWorker]struct{}, n),
		limit:          n,
		oneShotReserve: oneShotReserveFor(n),
	}
	p.recurring = make(chan struct{}, cap(p.tasks)-p.oneShotReserve)
	for range n {
		p.startWorkerLocked()
	}
	return p
}

// startWorkerLocked spawns one worker and registers it. Called with p.mu
// held for writing.
func (p *workerPool) startWorkerLocked() {
	w := &poolWorker{retire: make(chan struct{})}
	p.workers[w] = struct{}{}
	p.wg.Add(1)
	go p.work(w)
}

// work pulls tasks until retired or the pool stops. Tasks wrap fn with the
// pool's bookkeeping before they reach this loop, so the recover here still
// catches application panics past the wrapper's defers.
func (p *workerPool) work(w *poolWorker) {
	defer p.wg.Done()
	defer func() {
		p.mu.Lock()
		delete(p.workers, w)
		p.mu.Unlock()
	}()
	for {
		select {
		case <-w.retire:
			return
		case fn, ok := <-p.tasks:
			if !ok {
				return
			}
			p.running.Add(1)
			func() {
				defer p.running.Add(-1)
				defer func() {
					if r := recover(); r != nil {
						slog.Error("worker panic recovered", "error", r, "stack", string(debug.Stack()))
					}
				}()
				fn()
			}()
		}
	}
}

// pause makes the pool refuse new submissions for good. Admitted work keeps
// running, and dispatchGated coordinators admitted before the pause still
// queue their job. The self-update drain pauses the pools, then waits for
// idle.
func (p *workerPool) pause() {
	p.paused.Store(true)
}

// submitMode queues fn. With wait it applies backpressure until a queue slot
// opens or ctx is cancelled, which recurring schedulers use since they run
// one goroutine per assignment; such submissions take a recurring-lane token
// first, so they cannot consume the reserved one-shot slots. Without wait it
// fails at once on a full queue, so the session event loop never stalls;
// those submissions are one-shot and may use the whole queue. A paused pool
// refuses.
func (p *workerPool) submitMode(ctx context.Context, fn func(), wait bool) bool {
	lane := laneOneShot
	if wait {
		lane = laneRecurring
	}
	return p.admitLane(ctx, fn, wait, true, lane)
}

// admitLane is submitMode with an explicit lane, and with the pause check
// optional: dispatchGated skips it for coordinators the pool already counts
// as busy. It holds p.mu for reading across the whole admission so stop
// cannot close the channel under a blocked queue send — stop blocks on the
// same lock until waiting admissions return.
func (p *workerPool) admitLane(ctx context.Context, fn func(), wait, honorPause bool, lane admissionLane) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	// Recurring work takes its lane token before the busy increment so a
	// token can never be held by work the pool refused. The token guards
	// queue occupancy for the A5 reserve and frees at dequeue; the
	// recurringInFlight counter keeps the queued-plus-running figure for
	// stats after the token is released.
	if lane == laneRecurring {
		select {
		case p.recurring <- struct{}{}:
			p.recurringInFlight.Add(1)
		case <-ctx.Done():
			return false
		}
	}
	releaseLane := func() {
		if lane == laneRecurring {
			<-p.recurring
			p.recurringInFlight.Add(-1)
		}
	}
	// Count the task before it can reach a worker so busy never dips to
	// zero between admission and completion.
	p.busy.Add(1)
	// The pause is read after the busy increment, and pause stores before
	// the drain reads busy. Either the drain sees this task as busy, or
	// this read sees the pause.
	if honorPause && p.paused.Load() {
		p.busy.Add(-1)
		releaseLane()
		return false
	}
	task := func() {
		defer p.busy.Add(-1)
		if lane == laneRecurring {
			defer p.recurringInFlight.Add(-1)
			// The lane token guards queue slots for the A5 one-shot
			// reserve, so it frees when the task leaves the queue.
			// Running work is bounded by the worker limit, not the lane.
			<-p.recurring
		}
		fn()
	}
	if wait {
		select {
		case p.tasks <- task:
			return true
		case <-ctx.Done():
			p.busy.Add(-1)
			releaseLane()
			return false
		}
	}
	select {
	case p.tasks <- task:
		return true
	default:
		p.busy.Add(-1)
		releaseLane()
		return false
	}
}

// setWorkerLimit resizes the pool to limit live workers, at least one.
// Growing starts workers immediately; shrinking closes retire channels so
// surplus workers exit after finishing their current task. A closed pool
// ignores the call.
func (p *workerPool) setWorkerLimit(limit int) {
	limit = max(1, limit)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.limit = limit
	for len(p.workers) < limit {
		p.startWorkerLocked()
	}
	for len(p.workers) > limit {
		for w := range p.workers {
			close(w.retire)
			delete(p.workers, w)
			break
		}
	}
}

// workerLimit reports the configured worker count.
func (p *workerPool) workerLimit() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.limit
}

// stats returns the heartbeat load snapshot; see workerPoolStats.
func (p *workerPool) stats() workerPoolStats {
	p.mu.RLock()
	limit := p.limit
	workers := len(p.workers)
	p.mu.RUnlock()
	return workerPoolStats{
		Limit:             limit,
		Workers:           workers,
		Busy:              p.busy.Load(),
		Running:           p.running.Load(),
		Queued:            len(p.tasks),
		RecurringInFlight: int(p.recurringInFlight.Load()),
		RecurringCapacity: cap(p.recurring),
		OneShotReserve:    p.oneShotReserve,
	}
}

// refusing reports whether admission would be refused immediately: the pool
// is stopped or paused for a self-update drain.
func (p *workerPool) refusing() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed || p.paused.Load()
}

// idle reports whether every admitted coordinator and task has finished.
func (p *workerPool) idle() bool {
	return p.busy.Load() == 0
}

// dispatchFailure says why dispatchGated could not queue a job.
type dispatchFailure int

const (
	// dispatchCancelled: the gate context ended during jitter or gate wait.
	dispatchCancelled dispatchFailure = iota
	// dispatchBacklogged: the target already has its share of parked
	// waiters, or every dispatch slot is parked on some busy target.
	dispatchBacklogged
	// dispatchQueueFull: the pool queue is full (or the pool stopped).
	dispatchQueueFull
)

// dispatchGated queues a one-shot job without blocking the caller. After
// delay it takes the target's gate and submits run, which receives the gate
// release and must call it when the job ends. Only a job whose target is
// already busy parks a goroutine — and a dispatch slot — on the gate, and one
// target may park at most a quarter of the slots, so a stalled device cannot
// starve the rest of the pool. The queued job lands in the one-shot lane, so
// recurring saturation cannot push it out of the reserved slots. fail is
// called exactly once on any path that does not queue run. delay is passed
// in so the coordinator reads no package globals, which keeps tests that
// restore the jitter bound race-free.
func (p *workerPool) dispatchGated(
	gateCtx, submitCtx context.Context,
	gates *targetGates,
	key string,
	delay time.Duration,
	run func(release func()),
	fail func(dispatchFailure),
) {
	p.busy.Add(1)
	time.AfterFunc(delay, func() {
		defer p.busy.Add(-1)
		if gateCtx.Err() != nil {
			fail(dispatchCancelled)
			return
		}
		release, holders := gates.tryAcquire(key)
		if release == nil {
			if holders-1 >= p.targetWaitLimit() || !p.acquireDispatch() {
				fail(dispatchBacklogged)
				return
			}
			release = gates.acquire(gateCtx, key)
			p.releaseDispatch()
			if release == nil {
				fail(dispatchCancelled)
				return
			}
		}
		// The gate moves into the queued task so the worker frees it on
		// every exit path — success, panic past the pool's recover, or the
		// task's early cancelled-context return.
		if !p.admitLane(submitCtx, func() { run(release) }, false, false, laneOneShot) {
			release()
			fail(dispatchQueueFull)
		}
	})
}

// targetWaitLimit caps how many jobs for one target may park on its gate.
func (p *workerPool) targetWaitLimit() int {
	return max(1, cap(p.dispatch)/4)
}

// acquireDispatch takes a slot for a coordinator about to park on a busy
// target's gate. Returns false when every slot is already parked, and the
// job is reported AGENT_BUSY instead of waiting.
func (p *workerPool) acquireDispatch() bool {
	select {
	case p.dispatch <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseDispatch frees a coordinator slot once its gate wait ends. Must be called exactly once per
// successful acquireDispatch.
func (p *workerPool) releaseDispatch() {
	<-p.dispatch
}

// targetGates serializes job execution per device target across every worker
// pool. Each key maps to a one-slot semaphore: a job for a target that is
// already being worked waits instead of running concurrently with it.
// Entries are reference counted and deleted when the last acquirer releases,
// so keys for one-off targets do not accumulate for the life of a session.
type targetGates struct {
	mu    sync.Mutex
	gates map[string]*gateEntry
}

// gateEntry is one target's semaphore. refs counts every acquirer holding or
// waiting on the semaphore; the entry is deleted only at zero, so a waiter
// can never lose its gate to an early delete.
type gateEntry struct {
	sem  chan struct{}
	refs int
}

// acquire returns the release function for the target's semaphore, or nil when
// ctx is cancelled before or while waiting. A nil key never blocks.
func (g *targetGates) acquire(ctx context.Context, key string) func() {
	if g == nil || key == "" {
		return func() {}
	}
	if ctx.Err() != nil {
		return nil
	}
	g.mu.Lock()
	if g.gates == nil {
		g.gates = make(map[string]*gateEntry)
	}
	e, ok := g.gates[key]
	if !ok {
		e = &gateEntry{sem: make(chan struct{}, 1)}
		g.gates[key] = e
	}
	e.refs++
	g.mu.Unlock()

	dropRef := func() {
		g.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(g.gates, key)
		}
		g.mu.Unlock()
	}

	select {
	case e.sem <- struct{}{}:
		// A context cancelled after winning the send is handled by the
		// caller's submit, which fails fast on ctx.Err() and releases.
		return func() {
			<-e.sem
			dropRef()
		}
	case <-ctx.Done():
		dropRef()
		return nil
	}
}

// tryAcquire takes the target's semaphore without waiting. It returns the
// release function, or nil plus the number of jobs holding or waiting on the
// target when it is busy. A nil key never blocks.
func (g *targetGates) tryAcquire(key string) (func(), int) {
	if g == nil || key == "" {
		return func() {}, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gates == nil {
		g.gates = make(map[string]*gateEntry)
	}
	e, ok := g.gates[key]
	if !ok {
		e = &gateEntry{sem: make(chan struct{}, 1)}
		g.gates[key] = e
	}
	select {
	case e.sem <- struct{}{}:
	default:
		return nil, e.refs
	}
	e.refs++
	return func() {
		<-e.sem
		g.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(g.gates, key)
		}
		g.mu.Unlock()
	}, 0
}

// stop closes the task channel and waits for all workers to finish. Workers
// retired by setWorkerLimit have already left; the rest drain every queued
// task before the wait returns.
func (p *workerPool) stop() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.tasks)
		p.mu.Unlock()
		p.wg.Wait()
	})
}
