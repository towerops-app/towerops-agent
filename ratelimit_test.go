// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
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

	// Inside the burst wait never blocks.
	for range 100 {
		if !b.wait(context.Background()) {
			t.Fatal("wait failed inside the burst")
		}
	}

	// Past the burst each token costs 1ms.
	start := time.Now()
	if !b.wait(context.Background()) {
		t.Fatal("wait failed past the burst")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Microsecond {
		t.Fatalf("wait returned after %v, want ~1ms", elapsed)
	}

	// Debt accumulated by charge is paid off by the next wait.
	b.charge()
	start = time.Now()
	if !b.wait(context.Background()) {
		t.Fatal("wait failed with outstanding debt")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Microsecond {
		t.Fatalf("wait returned after %v, want ~1ms of debt repayment", elapsed)
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
	if !b.wait(context.Background()) {
		t.Fatal("disabled bucket wait blocked")
	}
}

func TestDispatchJitterBounds(t *testing.T) {
	orig := dispatchJitterMax
	dispatchJitterMax = 50 * time.Millisecond
	t.Cleanup(func() { dispatchJitterMax = orig })

	sawNonzero := false
	for range 200 {
		d := dispatchJitter()
		if d < 0 || d >= 50*time.Millisecond {
			t.Fatalf("dispatchJitter = %v, want [0, 50ms)", d)
		}
		if d > 0 {
			sawNonzero = true
		}
	}
	if !sawNonzero {
		t.Fatal("dispatchJitter always returned 0; jitter is not applied")
	}
}

func TestJitterDispatchSleeps(t *testing.T) {
	// A no-op implementation would return in nanoseconds; sleeping 20ms must
	// take at least most of the requested delay.
	start := time.Now()
	jitterDispatch(context.Background(), 20*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Fatalf("jitterDispatch returned after %v, want ~20ms sleep", elapsed)
	}

	// A non-positive delay must not sleep at all.
	start = time.Now()
	jitterDispatch(context.Background(), 0)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("jitterDispatch(0) blocked %v, want immediate return", elapsed)
	}
}

func TestJitterDispatchCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		jitterDispatch(ctx, time.Hour)
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

func TestSNMPSentHook(t *testing.T) {
	current := time.Now()
	b := newTokenBucket(100, func() time.Time { return current })

	// Drain the burst, then prove each hook call charges one token: the next
	// reserve must report debt.
	for range 10 {
		b.charge()
	}
	if d := b.reserve(); d != 10*time.Millisecond {
		t.Fatalf("reserve after burst waited %v, want 10ms", d)
	}
	hook := snmpSentHook(b)
	hook(nil)
	if d := b.reserve(); d != 30*time.Millisecond {
		t.Fatalf("reserve after OnSent charge waited %v, want 30ms", d)
	}
}

// The querier wrapper must settle the bucket before delegating, so pacing
// happens outside gosnmp's request deadline.
func TestRateLimitedQuerier(t *testing.T) {
	t.Cleanup(func() { setSNMPPDURate(defaultSNMPPDURate) })
	setSNMPPDURate(0)

	mock := &mockSnmpQuerier{
		getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{}, nil
		},
		walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
			return []gosnmp.SnmpPDU{{Name: rootOid + ".1"}}, nil
		},
		walkStepFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
			return []gosnmp.SnmpPDU{{Name: rootOid + ".1"}}, nil
		},
	}
	q := &rateLimitedQuerier{ctx: context.Background(), q: mock}

	if _, err := q.Get([]string{"1.3.6.1"}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := q.WalkAll("1.3.6.1"); err != nil {
		t.Fatalf("WalkAll: %v", err)
	}
	if !mock.walkAllCalled {
		t.Fatal("WalkAll did not delegate")
	}
	if _, err := q.BulkWalkAll("1.3.6.1"); err != nil {
		t.Fatalf("BulkWalkAll: %v", err)
	}
	if !mock.bulkWalkCalled {
		t.Fatal("BulkWalkAll did not delegate")
	}
	var walked []gosnmp.SnmpPDU
	if err := q.Walk("1.3.6.1", func(p gosnmp.SnmpPDU) error {
		walked = append(walked, p)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(walked) != 1 {
		t.Fatalf("Walk delivered %d PDUs, want 1", len(walked))
	}
	if err := q.BulkWalk("1.3.6.1", func(p gosnmp.SnmpPDU) error { return nil }); err != nil {
		t.Fatalf("BulkWalk: %v", err)
	}
	if len(mock.bulkWalkRoots) != 1 {
		t.Fatal("BulkWalk did not delegate")
	}
}

// A cancelled context must surface through wait so a queued request does
// not run against a dead job.
func TestRateLimitedQuerierCancelledContext(t *testing.T) {
	t.Cleanup(func() { setSNMPPDURate(defaultSNMPPDURate) })
	setSNMPPDURate(1) // 1 token/s: the second wait has ~1s of debt
	snmpPDUs.charge()
	snmpPDUs.charge()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delegated := false
	mock := &mockSnmpQuerier{
		getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			delegated = true
			return &gosnmp.SnmpPacket{}, nil
		},
	}
	q := &rateLimitedQuerier{ctx: ctx, q: mock}
	_, err := q.Get([]string{"1.3.6.1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want context.Canceled", err)
	}
	if _, err := q.WalkAll("1.3.6.1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("WalkAll error = %v, want context.Canceled", err)
	}
	if _, err := q.BulkWalkAll("1.3.6.1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("BulkWalkAll error = %v, want context.Canceled", err)
	}
	if err := q.Walk("1.3.6.1", func(p gosnmp.SnmpPDU) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Walk error = %v, want context.Canceled", err)
	}
	if err := q.BulkWalk("1.3.6.1", func(p gosnmp.SnmpPDU) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("BulkWalk error = %v, want context.Canceled", err)
	}
	if delegated {
		t.Fatal("querier delegated to the device despite cancellation")
	}
}
