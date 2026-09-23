// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestTokenBucketReserve(t *testing.T) {
	now := time.Now()
	current := now
	b := newTokenBucket(100, func() time.Time { return current })

	// The burst covers a tenth of a second: 10 immediate tokens at 100/s.
	for i := range 10 {
		if d := b.reserve(); d != 0 {
			t.Fatalf("reserve %d waited %v, want 0 within burst", i, d)
		}
	}
	// Past the burst, each token costs 10ms and reservations queue up.
	if d := b.reserve(); d != 10*time.Millisecond {
		t.Fatalf("first post-burst reserve waited %v, want 10ms", d)
	}
	if d := b.reserve(); d != 20*time.Millisecond {
		t.Fatalf("second post-burst reserve waited %v, want 20ms", d)
	}

	// Advancing 30ms refills 3 tokens, absorbing the queued debt.
	current = current.Add(30 * time.Millisecond)
	if d := b.reserve(); d != 0 {
		t.Fatalf("reserve after refill waited %v, want 0", d)
	}
	if d := b.reserve(); d != 10*time.Millisecond {
		t.Fatalf("reserve after refill waited %v, want 10ms", d)
	}
}

func TestTokenBucketWait(t *testing.T) {
	b := newTokenBucket(1000, nil) // 1ms per token, burst of 100
	for range 100 {
		if !b.wait(context.Background()) {
			t.Fatal("wait failed inside the burst")
		}
	}
	start := time.Now()
	if !b.wait(context.Background()) {
		t.Fatal("wait failed past the burst")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Microsecond {
		t.Fatalf("wait returned after %v, want ~1ms", elapsed)
	}
}

func TestTokenBucketWaitHonoursCancellation(t *testing.T) {
	b := newTokenBucket(1, nil) // 1 token/s: the second wait is ~1s out
	if !b.wait(context.Background()) {
		t.Fatal("first wait failed inside the burst")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- b.wait(ctx) }()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("wait succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled wait did not return")
	}
}

func TestTokenBucketDisabled(t *testing.T) {
	b := newTokenBucket(0, nil)
	for range 1000 {
		if d := b.reserve(); d != 0 {
			t.Fatalf("disabled bucket waited %v, want 0", d)
		}
	}
}

func TestDispatchJitterBounds(t *testing.T) {
	orig := dispatchJitterMax
	dispatchJitterMax = 50 * time.Millisecond
	t.Cleanup(func() { dispatchJitterMax = orig })

	for range 200 {
		d := dispatchJitter()
		if d < 0 || d >= 50*time.Millisecond {
			t.Fatalf("dispatchJitter = %v, want [0, 50ms)", d)
		}
	}
}

func TestJitterDispatchSleepsWithinBound(t *testing.T) {
	orig := dispatchJitterMax
	dispatchJitterMax = 20 * time.Millisecond
	t.Cleanup(func() { dispatchJitterMax = orig })

	start := time.Now()
	jitterDispatch(context.Background())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("jitterDispatch blocked %v, want < 20ms", elapsed)
	}
}

func TestJitterDispatchCancelled(t *testing.T) {
	orig := dispatchJitterMax
	dispatchJitterMax = time.Hour
	t.Cleanup(func() { dispatchJitterMax = orig })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		jitterDispatch(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("jitterDispatch did not return on a cancelled context")
	}
}

func TestSetSNMPPDURate(t *testing.T) {
	t.Cleanup(func() { setSNMPPDURate(defaultSNMPPDURate) })
	setSNMPPDURate(0)
	if d := snmpPDUs.reserve(); d != 0 {
		t.Fatalf("disabled limiter waited %v, want 0", d)
	}
	setSNMPPDURate(100)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snmpPDUs.reserve()
		}()
	}
	wg.Wait()
}
