package main

import "sync"

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
				fn()
			}
		}()
	}
	return p
}

// submit enqueues a task. Blocks if all workers are busy and the queue is full.
func (p *workerPool) submit(fn func()) {
	p.tasks <- fn
}

// stop closes the task channel and waits for all workers to finish.
func (p *workerPool) stop() {
	p.once.Do(func() {
		close(p.tasks)
		p.wg.Wait()
	})
}
