// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	t.Run("executes all tasks", func(t *testing.T) {
		pool := newWorkerPool(4)
		defer pool.stop()

		var count atomic.Int32
		accepted := 0
		for i := 0; i < 100; i++ {
			if pool.submit(context.Background(), func() {
				count.Add(1)
			}) {
				accepted++
			}
		}

		pool.stop()
		if got := count.Load(); got != int32(accepted) { //nolint:gosec // accepted <= 100
			t.Errorf("got %d completions, want %d accepted tasks", got, accepted)
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

func TestWorkerPoolSubmitAfterStop(t *testing.T) {
	pool := newWorkerPool(1)
	pool.stop()
	if pool.submit(context.Background(), func() { t.Error("stopped pool executed task") }) {
		t.Fatal("stopped pool accepted task")
	}
}

func TestWorkerPoolConcurrentSubmitAndStop(t *testing.T) {
	for range 100 {
		pool := newWorkerPool(1)
		var submitters sync.WaitGroup
		start := make(chan struct{})
		for range 8 {
			submitters.Add(1)
			go func() {
				defer submitters.Done()
				<-start
				for range 100 {
					pool.submit(context.Background(), func() {})
				}
			}()
		}
		close(start)
		pool.stop()
		submitters.Wait()
	}
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

func TestWorkerPoolRejectsImmediatelyWhenFull(t *testing.T) {
	pool := newWorkerPool(1)
	blocker := make(chan struct{})
	started := make(chan struct{})
	pool.submit(context.Background(), func() { close(started); <-blocker })
	<-started
	for range cap(pool.tasks) {
		if !pool.submit(context.Background(), func() { <-blocker }) {
			t.Fatal("queue rejected a task before reaching capacity")
		}
	}
	start := time.Now()
	if pool.submit(context.Background(), func() {}) {
		t.Fatal("full queue accepted another task")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("full queue rejection blocked for %v", elapsed)
	}
	close(blocker)
	pool.stop()
}
