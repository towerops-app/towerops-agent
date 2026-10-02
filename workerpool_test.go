// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
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

	// Submit a normal function - the worker should still be alive
	done := make(chan struct{})
	ok := pool.submit(context.Background(), func() { close(done) })
	if !ok {
		t.Fatal("expected submit to succeed after panic recovery")
	}

	select {
	case <-done:
		// Worker survived the panic
	case <-time.After(2 * time.Second):
		t.Error("timed out - worker did not survive panic")
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

func TestWorkerPoolSubmitWaitStopsOnCancellation(t *testing.T) {
	pool := newWorkerPool(1)
	blocker := make(chan struct{})
	started := make(chan struct{})
	if !pool.submit(context.Background(), func() {
		close(started)
		<-blocker
	}) {
		t.Fatal("pool rejected blocker")
	}
	<-started
	for range cap(pool.tasks) {
		if !pool.submit(context.Background(), func() { <-blocker }) {
			t.Fatal("pool rejected queued blocker")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() {
		result <- pool.submitWait(ctx, func() { t.Error("cancelled submission executed") })
	}()
	cancel()

	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("cancelled waiting submission was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting submission did not unblock on cancellation")
	}

	close(blocker)
	pool.stop()
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

func TestTargetGates(t *testing.T) {
	t.Run("same target serializes", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "10.0.0.1")

		acquired := make(chan func(), 1)
		go func() { acquired <- gates.acquire(context.Background(), "10.0.0.1") }()
		select {
		case <-acquired:
			t.Fatal("second acquire for the same target did not wait")
		case <-time.After(50 * time.Millisecond):
		}
		release()
		select {
		case r := <-acquired:
			r()
		case <-time.After(time.Second):
			t.Fatal("acquire did not proceed after release")
		}
	})

	t.Run("different targets do not block", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "10.0.0.1")
		defer release()
		done := make(chan func(), 1)
		go func() { done <- gates.acquire(context.Background(), "10.0.0.2") }()
		select {
		case r := <-done:
			r()
		case <-time.After(time.Second):
			t.Fatal("acquire for a different target blocked")
		}
	})

	t.Run("cancelled acquire returns nil", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "10.0.0.1")
		defer release()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r := gates.acquire(ctx, "10.0.0.1"); r != nil {
			t.Fatal("cancelled acquire returned a release function")
		}
	})

	t.Run("empty key never blocks", func(t *testing.T) {
		gates := &targetGates{}
		r := gates.acquire(context.Background(), "")
		if r == nil {
			t.Fatal("empty key acquire returned nil")
		}
		r()
	})

	t.Run("tryAcquire with empty key or nil gates never blocks", func(t *testing.T) {
		gates := &targetGates{}
		r, holders := gates.tryAcquire("")
		if r == nil || holders != 0 {
			t.Fatalf("empty key tryAcquire = (%v, %d), want release and 0 holders", r != nil, holders)
		}
		r()
		var nilGates *targetGates
		r, holders = nilGates.tryAcquire("10.0.0.1")
		if r == nil || holders != 0 {
			t.Fatalf("nil gates tryAcquire = (%v, %d), want release and 0 holders", r != nil, holders)
		}
		r()
	})

	t.Run("pre-cancelled context never takes the gate", func(t *testing.T) {
		gates := &targetGates{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// A single acquire has an even chance of slipping through the old
		// select; looping makes a regression effectively certain to fail.
		for range 64 {
			if r := gates.acquire(ctx, "10.0.0.1"); r != nil {
				r()
				t.Fatal("pre-cancelled acquire returned a release function")
			}
		}
		if len(gates.gates) != 0 {
			t.Fatalf("cancelled acquire left %d gate entries", len(gates.gates))
		}
	})

	t.Run("released gate is deleted", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "job:123")
		release()
		if _, ok := gates.gates["job:123"]; ok {
			t.Fatal("released gate key was not deleted")
		}
	})

	t.Run("waiting acquirer keeps the gate alive", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "10.0.0.1")

		waiter := make(chan func(), 1)
		go func() { waiter <- gates.acquire(context.Background(), "10.0.0.1") }()
		waitForGateRefs(t, gates, "10.0.0.1", 2)

		// The holder releasing must not delete a gate that still has a
		// waiter; if it did, the waiter would sit on an orphaned channel.
		release()
		r := <-waiter

		// The waiter's gate is still the registered one, so a third
		// acquirer must block until the waiter releases.
		third := make(chan func(), 1)
		go func() { third <- gates.acquire(context.Background(), "10.0.0.1") }()
		select {
		case <-third:
			t.Fatal("gate deleted while a waiter was queued")
		case <-time.After(50 * time.Millisecond):
		}
		r()
		select {
		case tr := <-third:
			tr()
		case <-time.After(time.Second):
			t.Fatal("acquire did not proceed after release")
		}
		if len(gates.gates) != 0 {
			t.Fatalf("%d gate entries left after all releases", len(gates.gates))
		}
	})

	t.Run("cancelled waiter does not delete a live gate", func(t *testing.T) {
		gates := &targetGates{}
		release := gates.acquire(context.Background(), "10.0.0.1")
		defer release()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan func(), 1)
		go func() { done <- gates.acquire(ctx, "10.0.0.1") }()
		waitForGateRefs(t, gates, "10.0.0.1", 2)
		cancel()
		if r := <-done; r != nil {
			t.Fatal("cancelled waiter acquired the gate")
		}
		waitForGateRefs(t, gates, "10.0.0.1", 1)
		if _, ok := gates.gates["10.0.0.1"]; !ok {
			t.Fatal("cancelled waiter removed the holder's gate")
		}
	})

	t.Run("concurrent churn leaves no keys", func(t *testing.T) {
		gates := &targetGates{}
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := fmt.Sprintf("10.0.0.%d", i%3)
				for range 25 {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					if r := gates.acquire(ctx, key); r != nil {
						r()
					}
					cancel()
				}
			}(i)
		}
		wg.Wait()
		if len(gates.gates) != 0 {
			t.Fatalf("%d gate entries left after concurrent churn", len(gates.gates))
		}
	})
}

// waitForGateRefs polls until the gate for key reports want references.
func waitForGateRefs(t *testing.T, gates *targetGates, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		gates.mu.Lock()
		refs := 0
		if e, ok := gates.gates[key]; ok {
			refs = e.refs
		}
		gates.mu.Unlock()
		if refs == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate %q has %d refs, want %d", key, refs, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// An uncontended one-shot job goes straight to the queue: dispatch slots
// held by jobs parked on other targets must not reject it while workers idle.
func TestDispatchGatedUncontendedIgnoresParkedSlots(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()
	for range cap(pool.dispatch) {
		pool.acquireDispatch()
	}
	defer func() {
		for range cap(pool.dispatch) {
			pool.releaseDispatch()
		}
	}()

	gates := &targetGates{}
	ran := make(chan struct{})
	pool.dispatchGated(context.Background(), context.Background(), gates, "10.0.0.1", 0,
		func(release func()) { defer release(); close(ran) },
		func(r dispatchFailure) { t.Errorf("dispatch failed: %v", r) })
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("uncontended job never ran")
	}
}

// One stalled target may park only its share of the dispatch slots, so jobs
// for other targets keep flowing.
func TestDispatchGatedTargetWaitLimit(t *testing.T) {
	pool := newWorkerPool(4)
	defer pool.stop()
	gates := &targetGates{}
	hold := gates.acquire(context.Background(), "slow")

	limit := pool.targetWaitLimit()
	if limit >= cap(pool.dispatch) {
		t.Fatalf("target wait limit %d does not leave slots for other targets", limit)
	}
	var ran atomic.Int32
	for range limit {
		pool.dispatchGated(context.Background(), context.Background(), gates, "slow", 0,
			func(release func()) { defer release(); ran.Add(1) },
			func(r dispatchFailure) { t.Errorf("parked job failed: %v", r) })
	}
	waitForGateRefs(t, gates, "slow", limit+1)

	failed := make(chan dispatchFailure, 1)
	pool.dispatchGated(context.Background(), context.Background(), gates, "slow", 0,
		func(release func()) { release(); t.Error("over-limit job ran") },
		func(r dispatchFailure) { failed <- r })
	select {
	case r := <-failed:
		if r != dispatchBacklogged {
			t.Fatalf("failure = %v, want dispatchBacklogged", r)
		}
	case <-time.After(time.Second):
		t.Fatal("over-limit job was not rejected")
	}

	other := make(chan struct{})
	pool.dispatchGated(context.Background(), context.Background(), gates, "fast", 0,
		func(release func()) { defer release(); close(other) },
		func(r dispatchFailure) { t.Errorf("other target failed: %v", r) })
	select {
	case <-other:
	case <-time.After(time.Second):
		t.Fatal("a stalled target starved another target")
	}

	hold()
	deadline := time.Now().Add(time.Second)
	for ran.Load() != int32(limit) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d parked jobs ran after release", ran.Load(), limit)
		}
		time.Sleep(time.Millisecond)
	}
	for !pool.idle() {
		if time.Now().After(deadline) {
			t.Fatal("pool never went idle")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatchGatedCancelledDuringJitter(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()
	ctx, cancel := context.WithCancel(context.Background())
	failed := make(chan dispatchFailure, 1)
	pool.dispatchGated(ctx, ctx, &targetGates{}, "k", 20*time.Millisecond,
		func(release func()) { release(); t.Error("cancelled job ran") },
		func(r dispatchFailure) { failed <- r })
	if pool.idle() {
		t.Fatal("pool idle while a coordinator was pending")
	}
	cancel()
	select {
	case r := <-failed:
		if r != dispatchCancelled {
			t.Fatalf("failure = %v, want dispatchCancelled", r)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled job never reported")
	}
}
