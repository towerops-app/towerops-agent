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

// A5: a recurring schedule that saturates its lane must not be able to take
// the queue slots reserved for one-shot work.
func TestWorkerPoolReservesOneShotCapacity(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()

	stats := pool.stats()
	if stats.OneShotReserve != 1 || stats.RecurringCapacity != cap(pool.tasks)-1 {
		t.Fatalf("reserve = %d, recurring capacity = %d, want 1 and %d",
			stats.OneShotReserve, stats.RecurringCapacity, cap(pool.tasks)-1)
	}

	ctx := context.Background()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var startOnce sync.Once

	// Recurring lane: one running task plus a full recurring lane of queued
	// tasks. The worker is busy, so every queued task occupies a buffer slot.
	block := func() {
		startOnce.Do(func() { close(started) })
		<-release
	}
	if !pool.submitMode(ctx, block, true) {
		t.Fatal("recurring submission rejected on an empty pool")
	}
	<-started
	for range stats.RecurringCapacity - 1 {
		if !pool.submitMode(ctx, block, true) {
			t.Fatal("recurring submission rejected before its lane filled")
		}
	}
	stats = pool.stats()
	if stats.RecurringInFlight != stats.RecurringCapacity {
		t.Fatalf("recurring in flight = %d, want %d", stats.RecurringInFlight, stats.RecurringCapacity)
	}

	// The reserved slot stays reachable for one-shot work.
	ran := make(chan struct{})
	if !pool.submitMode(ctx, func() { close(ran) }, false) {
		t.Fatal("saturated recurring lane rejected a one-shot job")
	}

	// Additional recurring submissions wait for lane tokens; they are not
	// refused, just backpressured, and cancelling the scheduler goroutine
	// releases the wait without running the task.
	rejected := make(chan bool, 1)
	recurCtx, cancelRecur := context.WithCancel(ctx)
	go func() {
		rejected <- pool.submitMode(recurCtx, func() { t.Error("token-blocked task ran") }, true)
	}()
	select {
	case <-rejected:
		t.Fatal("recurring submission bypassed its lane capacity")
	case <-time.After(20 * time.Millisecond):
	}
	cancelRecur()
	if <-rejected {
		t.Fatal("cancelled recurring submission was accepted")
	}

	close(release)
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted one-shot job never ran")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !pool.idle() {
		if time.Now().After(deadline) {
			t.Fatal("pool never drained after the one-shot job")
		}
		time.Sleep(time.Millisecond)
	}
	if got := pool.stats().RecurringInFlight; got != 0 {
		t.Fatalf("recurring lane retained %d tokens after drain", got)
	}
}

// A4: the pool reports its dynamic limit and live load for the heartbeat.
func TestWorkerPoolStatsTrackLoad(t *testing.T) {
	pool := newWorkerPool(2)
	defer pool.stop()

	release := make(chan struct{})
	var running sync.WaitGroup
	started := make(chan struct{}, 8)
	task := func() {
		running.Add(1)
		started <- struct{}{}
		<-release
		running.Done()
	}
	for range 5 {
		if !pool.submitMode(context.Background(), task, true) {
			t.Fatal("recurring submission rejected below lane capacity")
		}
	}
	// Only the worker limit runs immediately; the rest are queued and their
	// starts depend on releasing these tasks.
	for range 2 {
		<-started
	}

	stats := pool.stats()
	if stats.Limit != 2 || stats.Workers != 2 {
		t.Fatalf("limit/workers = %d/%d, want 2/2", stats.Limit, stats.Workers)
	}
	if stats.Busy != 5 || stats.Running != 2 || stats.Queued != 3 {
		t.Fatalf("busy/running/queued = %d/%d/%d, want 5/2/3",
			stats.Busy, stats.Running, stats.Queued)
	}
	if stats.RecurringInFlight != 5 {
		t.Fatalf("recurring in flight = %d, want 5", stats.RecurringInFlight)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for !pool.idle() {
		if time.Now().After(deadline) {
			t.Fatal("pool never drained")
		}
		time.Sleep(time.Millisecond)
	}
	if got := pool.stats(); got.RecurringInFlight != 0 || got.Queued != 0 || got.Running != 0 {
		t.Fatalf("stats after drain = %+v, want zeros", got)
	}
}

// A4: setWorkerLimit resizes the pool without losing queued work, and the
// worker count converges on the new limit after draining.
func TestWorkerPoolSetWorkerLimit(t *testing.T) {
	pool := newWorkerPool(3)
	defer pool.stop()

	release := make(chan struct{})
	blocker := make(chan struct{})
	if !pool.submitMode(context.Background(), func() { close(blocker); <-release }, true) {
		t.Fatal("pool rejected the blocker")
	}
	<-blocker

	pool.setWorkerLimit(3)
	stats := pool.stats()
	if stats.Limit != 3 || stats.Workers != 3 {
		t.Fatalf("limit/workers after grow = %d/%d, want 3/3", stats.Limit, stats.Workers)
	}

	var concurrent, maxConcurrent atomic.Int32
	var ran sync.WaitGroup
	for range 6 {
		ran.Add(1)
		if !pool.submitMode(context.Background(), func() {
			defer ran.Done()
			cur := concurrent.Add(1)
			for {
				old := maxConcurrent.Load()
				if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			concurrent.Add(-1)
		}, true) {
			t.Fatal("grown pool rejected a task")
		}
	}

	pool.setWorkerLimit(1)
	if got := pool.workerLimit(); got != 1 {
		t.Fatalf("worker limit = %d, want 1", got)
	}

	close(release)
	ran.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats := pool.stats()
		if stats.Workers == 1 && pool.idle() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool settled at %+v, want one drained worker", stats)
		}
		time.Sleep(time.Millisecond)
	}
	if max := maxConcurrent.Load(); max > 3 {
		t.Fatalf("max concurrency = %d, want <= 3 before the shrink", max)
	}
	pool.stop()
	if got := pool.stats(); got.Workers != 0 {
		t.Fatalf("%d workers survived stop", got.Workers)
	}
}

// A4/D1: the default SNMP concurrency scales with inventory size.
func TestSNMPWorkerLimitDefaults(t *testing.T) {
	tests := []struct {
		devices int
		want    int
	}{
		{0, 100},
		{150, 100},
		{299, 100},
		{300, 100},
		{301, 100},
		{900, 300},
		{3000, 1000},
	}
	for _, tt := range tests {
		if got := snmpWorkerLimit(tt.devices); got != tt.want {
			t.Errorf("snmpWorkerLimit(%d) = %d, want %d", tt.devices, got, tt.want)
		}
	}
	// An explicit --snmp-concurrency wins over the inventory-derived default.
	if got := snmpConcurrencyLimit(250, 3000); got != 250 {
		t.Fatalf("snmpConcurrencyLimit(250, 3000) = %d, want 250", got)
	}
	if got := snmpConcurrencyLimit(0, 3000); got != 1000 {
		t.Fatalf("snmpConcurrencyLimit(0, 3000) = %d, want 1000", got)
	}
	// Every pool keeps at least one reserved slot regardless of size.
	for n := range 12 {
		if reserve := oneShotReserveFor(n); reserve < 1 {
			t.Fatalf("oneShotReserveFor(%d) = %d, want >= 1", n, reserve)
		}
	}
}
