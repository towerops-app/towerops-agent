// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
)

// workerPool is a fixed-size goroutine pool for executing tasks.
type workerPool struct {
	tasks chan func()
	// dispatch bounds the coordinator goroutines that sleep through jitter
	// and then wait on a target gate before queueing a task. Without it a
	// large job push spawns an unbounded set of blocked goroutines that
	// bypass the pool-queue backpressure entirely. Sized to workers plus
	// queue depth so the gate saturates exactly when the pool does.
	dispatch chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
	mu       sync.RWMutex
	closed   bool
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

// submit enqueues a task without blocking. Interactive callers use it so a
// saturated protocol cannot stall the session event loop.
func (p *workerPool) submit(ctx context.Context, fn func()) bool {
	return p.submitMode(ctx, fn, false)
}

// submitWait applies backpressure until a queue slot opens or ctx is
// cancelled. Recurring schedulers have one goroutine per assignment, so
// waiting here spreads a burst without blocking unrelated work.
func (p *workerPool) submitWait(ctx context.Context, fn func()) bool {
	return p.submitMode(ctx, fn, true)
}

func (p *workerPool) submitMode(ctx context.Context, fn func(), wait bool) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	if !wait && ctx.Err() != nil {
		return false
	}
	if wait {
		select {
		case p.tasks <- fn:
			return true
		case <-ctx.Done():
			return false
		}
	}
	select {
	case p.tasks <- fn:
		return true
	default:
		return false
	}
}

// acquireDispatch takes a coordinator slot for a job that will spend its
// jitter and gate wait on a spawned goroutine. Returns false when every slot
// is taken, which means workers plus queue are saturated — the caller reports
// AGENT_BUSY instead of spawning.
func (p *workerPool) acquireDispatch() bool {
	select {
	case p.dispatch <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseDispatch frees a coordinator slot once the job it guarded has been
// handed to the pool (or abandoned). Must be called exactly once per
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
