package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	t.Run("executes all tasks", func(t *testing.T) {
		pool := newWorkerPool(4)
		defer pool.stop()

		var count atomic.Int32
		for i := 0; i < 100; i++ {
			pool.submit(context.Background(), func() {
				count.Add(1)
			})
		}

		pool.stop()
		if got := count.Load(); got != 100 {
			t.Errorf("got %d completions, want 100", got)
		}
	})

	t.Run("limits concurrency", func(t *testing.T) {
		pool := newWorkerPool(2)
		defer pool.stop()

		var concurrent atomic.Int32
		var maxConcurrent atomic.Int32

		for i := 0; i < 20; i++ {
			pool.submit(context.Background(), func() {
				cur := concurrent.Add(1)
				for {
					old := maxConcurrent.Load()
					if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
				concurrent.Add(-1)
			})
		}

		pool.stop()
		if max := maxConcurrent.Load(); max > 2 {
			t.Errorf("max concurrent was %d, want <= 2", max)
		}
	})

	t.Run("stop is idempotent", func(t *testing.T) {
		pool := newWorkerPool(2)
		pool.stop()
		pool.stop() // should not panic
	})
}

func TestWorkerPoolRecoversPanic(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()

	// Submit a function that panics
	pool.submit(context.Background(), func() { panic("boom") })

	// Give the panic time to be processed
	time.Sleep(50 * time.Millisecond)

	// Submit a normal function — the worker should still be alive
	done := make(chan struct{})
	ok := pool.submit(context.Background(), func() { close(done) })
	if !ok {
		t.Fatal("expected submit to succeed after panic recovery")
	}

	select {
	case <-done:
		// Worker survived the panic
	case <-time.After(2 * time.Second):
		t.Error("timed out — worker did not survive panic")
	}
}

func TestWorkerPoolSubmitRespectsContext(t *testing.T) {
	pool := newWorkerPool(1) // 1 worker, queue capacity 4
	defer pool.stop()

	blocker := make(chan struct{})

	// Occupy the single worker
	pool.submit(context.Background(), func() { <-blocker })

	// Fill the buffered queue (capacity = n*4 = 4)
	for i := 0; i < 4; i++ {
		pool.submit(context.Background(), func() { <-blocker })
	}

	// Now the queue is full and the worker is busy.
	// Submit with a cancelled context should return false immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok := pool.submit(ctx, func() { t.Error("should not execute") })
	if ok {
		t.Error("expected submit to return false with cancelled context")
	}

	// Unblock everything for cleanup
	close(blocker)
}
