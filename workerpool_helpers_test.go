// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"
)

// submit enqueues a task without blocking.
func (p *workerPool) submit(ctx context.Context, fn func()) bool {
	return p.submitMode(ctx, fn, false)
}

// submitWait blocks until a queue slot opens or ctx is cancelled.
func (p *workerPool) submitWait(ctx context.Context, fn func()) bool {
	return p.submitMode(ctx, fn, true)
}

// A paused pool refuses new submissions but still queues one-shot jobs that
// dispatchGated admitted before the pause, so the drain can wait them out.
func TestWorkerPoolPauseRefusesNewWorkOnly(t *testing.T) {
	pool := newWorkerPool(1)
	defer pool.stop()
	gates := &targetGates{}

	// Admitted before the pause: the coordinator is counted in busy.
	ran := make(chan struct{})
	failed := make(chan dispatchFailure, 1)
	pool.dispatchGated(context.Background(), context.Background(), gates, "t1", 20*time.Millisecond,
		func(release func()) { defer release(); close(ran) },
		func(reason dispatchFailure) { failed <- reason })
	pool.pause()

	if pool.submitMode(context.Background(), func() { t.Error("paused pool ran a new task") }, false) {
		t.Fatal("paused pool accepted a new submission")
	}
	if pool.submitMode(context.Background(), func() { t.Error("paused pool ran a new task") }, true) {
		t.Fatal("paused pool accepted a new waiting submission")
	}
	select {
	case <-ran:
	case reason := <-failed:
		t.Fatalf("pre-pause dispatch failed with %v", reason)
	case <-time.After(2 * time.Second):
		t.Fatal("pre-pause dispatch never ran")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !pool.idle() {
		if time.Now().After(deadline) {
			t.Fatal("pool never went idle after the refusals")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestJobPoolsPausePausesEveryPool(t *testing.T) {
	pools := testPools(t)
	pools.pause()
	for name, pool := range map[string]*workerPool{
		"snmp": pools.snmp, "mikrotik": pools.mikrotik, "ping": pools.ping, "checks": pools.checks,
	} {
		if !pool.paused.Load() {
			t.Fatalf("%s pool was not paused", name)
		}
	}
}
