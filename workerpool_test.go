package main

import (
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
			pool.submit(func() {
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
			pool.submit(func() {
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
