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
	tasks  chan func()
	wg     sync.WaitGroup
	once   sync.Once
	mu     sync.RWMutex
	closed bool
}

// newWorkerPool creates a pool with n worker goroutines.
func newWorkerPool(n int) *workerPool {
	p := &workerPool{
		tasks: make(chan func(), n*4),
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

// targetGates serializes job execution per device target across every worker
// pool. Each key maps to a one-slot semaphore: a job for a target that is
// already being worked waits instead of running concurrently with it.
type targetGates struct {
	mu    sync.Mutex
	gates map[string]chan struct{}
}

// acquire returns the release function for the target's semaphore, or nil when
// ctx is cancelled while waiting. A nil key never blocks.
func (g *targetGates) acquire(ctx context.Context, key string) func() {
	if g == nil || key == "" {
		return func() {}
	}
	g.mu.Lock()
	if g.gates == nil {
		g.gates = make(map[string]chan struct{})
	}
	sem, ok := g.gates[key]
	if !ok {
		sem = make(chan struct{}, 1)
		g.gates[key] = sem
	}
	g.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
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
