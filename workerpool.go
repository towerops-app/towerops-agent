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
	if ctx.Err() != nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
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
