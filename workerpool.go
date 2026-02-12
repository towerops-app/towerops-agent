package main

import (
	"context"
	"log/slog"
	"sync"
)

// workerPool is a fixed-size goroutine pool for executing tasks.
type workerPool struct {
	tasks chan func()
	wg    sync.WaitGroup
	once  sync.Once
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
							slog.Error("worker panic recovered", "error", r)
						}
					}()
					fn()
				}()
			}
		}()
	}
	return p
}

// submit enqueues a task. Returns false if the context is cancelled before the task can be queued.
func (p *workerPool) submit(ctx context.Context, fn func()) bool {
	select {
	case p.tasks <- fn:
		return true
	case <-ctx.Done():
		return false
	}
}

// stop closes the task channel and waits for all workers to finish.
func (p *workerPool) stop() {
	p.once.Do(func() {
		close(p.tasks)
		p.wg.Wait()
	})
}
