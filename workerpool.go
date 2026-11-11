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

// workerPool is a fixed-size goroutine pool for executing tasks.
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
	// paused refuses new submissions while admitted work finishes; set by
	// the self-update drain, never cleared.
	paused atomic.Bool
	wg     sync.WaitGroup
	once   sync.Once
	mu     sync.RWMutex
	closed bool
}

// newWorkerPool creates a pool with n worker goroutines.
func newWorkerPool(n int) *workerPool {
	p := &workerPool{
		tasks:    make(chan func(), n*4),
		dispatch: make(chan struct{}, n*5),
	}
	p.wg.Add(n)
	for range n {
		go func() {
			defer p.wg.Done()
			for fn := range p.tasks {
				func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("worker panic recovered", "error", r, "stack", string(debug.Stack()))
						}
					}()
					fn()
				}()
			}
		}()
	}
	return p
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
// one goroutine per assignment; without wait it fails at once on a full
// queue, so the session event loop never stalls. A paused pool refuses.
func (p *workerPool) submitMode(ctx context.Context, fn func(), wait bool) bool {
	return p.admit(ctx, fn, wait, true)
}

// admit is submitMode with the pause check optional: dispatchGated skips it
// for coordinators the pool already counts as busy.
func (p *workerPool) admit(ctx context.Context, fn func(), wait, honorPause bool) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	// Count the task before it can reach a worker so busy never dips to
	// zero between admission and completion.
	p.busy.Add(1)
	// The pause is read after the busy increment, and pause stores before
	// the drain reads busy. Either the drain sees this task as busy, or
	// this read sees the pause.
	if honorPause && p.paused.Load() {
		p.busy.Add(-1)
		return false
	}
	task := func() {
		defer p.busy.Add(-1)
		fn()
	}
	if wait {
		select {
		case p.tasks <- task:
			return true
		case <-ctx.Done():
			p.busy.Add(-1)
			return false
		}
	}
	select {
	case p.tasks <- task:
		return true
	default:
		p.busy.Add(-1)
		return false
	}
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
// starve the rest of the pool. fail is called exactly once on any path that
// does not queue run. delay is passed in so the coordinator reads no package
// globals, which keeps tests that restore the jitter bound race-free.
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
		if !p.admit(submitCtx, func() { run(release) }, false, false) {
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

// stop closes the task channel and waits for all workers to finish.
func (p *workerPool) stop() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.tasks)
		p.mu.Unlock()
		p.wg.Wait()
	})
}
