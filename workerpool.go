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

// submit enqueues a task without blocking the session event loop. Callers must
// handle false as overload (or cancellation).
func (p *workerPool) submit(ctx context.Context, fn func()) bool {
	if ctx.Err() != nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
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
