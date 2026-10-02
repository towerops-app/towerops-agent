// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// A cancelled wait must refund its reservation so a session teardown with
// many blocked requests does not leave debt that stalls the next session.
func TestTokenBucketWaitRefundsOnCancel(t *testing.T) {
	current := time.Now()
	b := newTokenBucket(1, func() time.Time { return current }) // 1 token/s

	// Consume the burst token, then cancel the second wait while it sleeps
	// off ~1s of debt. Without a refund the reservation stays on the bucket.
	if !b.wait(context.Background()) {
		t.Fatal("first wait failed inside the burst")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- b.wait(ctx) }()
	cancel()
	if ok := <-done; ok {
		t.Fatal("wait succeeded after cancellation")
	}

	// The refunded bucket holds 0 tokens: one more reserve owes one interval,
	// not the cancelled reservation's debt on top.
	if d := b.reserve(); d != time.Second {
		t.Fatalf("reserve after cancelled wait waited %v, want 1s — the reservation was not refunded", d)
	}
	if b.tokens != -1 {
		t.Fatalf("tokens = %v, want -1 after the refund plus one reserve", b.tokens)
	}
}

// waitDebt must block only until the next send is affordable and must not
// consume a token, so a paced walk does not charge the limiter twice per
// request.
func TestTokenBucketWaitDebt(t *testing.T) {
	b := newTokenBucket(100, nil) // burst of 10, then 10ms per token

	// No debt: returns immediately, even on a cancelled context.
	if !b.waitDebt(context.Background()) {
		t.Fatal("waitDebt failed with no debt")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if b.waitDebt(cancelled) {
		t.Fatal("waitDebt ignored a cancelled context")
	}

	// Push the balance negative like OnSent charge does: waitDebt must sleep
	// off the debt plus its own slot before returning.
	for range 11 {
		b.charge()
	}
	start := time.Now()
	if !b.waitDebt(context.Background()) {
		t.Fatal("waitDebt failed with outstanding debt")
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Fatalf("waitDebt returned after %v, want ~10ms of debt repayment", elapsed)
	}

	// waitDebt must not consume a token: the refiller repaid the debt, so the
	// balance is non-negative — a consumed token would leave it at -1.
	b.mu.Lock()
	tokens := b.tokens
	b.mu.Unlock()
	if tokens < 0 {
		t.Fatalf("tokens = %v after waitDebt, want >= 0 — it consumed a token", tokens)
	}
}

// Cancelling while waitDebt sleeps off its slot must return false and hand
// the reserved token back. The clock signals when waitDebt reserves, so the
// cancel always lands after the up-front ctx check and the timer path is
// exercised deterministically (the frozen clock keeps the debt outstanding).
func TestTokenBucketWaitDebtCancelled(t *testing.T) {
	fixed := time.Now()
	var armed atomic.Bool
	var once sync.Once
	reserved := make(chan struct{})
	b := newTokenBucket(1, func() time.Time {
		if armed.Load() {
			once.Do(func() { close(reserved) })
		}
		return fixed
	})
	b.charge() // burst goes negative: real debt to wait out
	b.charge()
	b.mu.Lock()
	before := b.tokens
	b.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	armed.Store(true)
	done := make(chan bool, 1)
	go func() { done <- b.waitDebt(ctx) }()
	<-reserved
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("waitDebt succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled waitDebt did not return")
	}
	b.mu.Lock()
	after := b.tokens
	b.mu.Unlock()
	if after != before {
		t.Fatalf("tokens = %v after cancelled waitDebt, want %v — reservation not refunded", after, before)
	}
}

// Concurrent walkers in waitDebt must get distinct, ordered slots. Polling for
// a non-negative balance woke every walker the instant the debt cleared, so
// they all sent at once — a burst far beyond the bucket's.
func TestTokenBucketWaitDebtSpreadsWalkers(t *testing.T) {
	b := newTokenBucket(100, nil) // burst of 10, then 10ms per token
	for range 11 {
		b.charge() // balance -1: ~10ms of debt shared by every walker
	}

	const walkers = 5
	start := time.Now()
	finished := make(chan time.Duration, walkers)
	for range walkers {
		go func() {
			if !b.waitDebt(context.Background()) {
				t.Error("waitDebt failed")
			}
			finished <- time.Since(start)
		}()
	}
	var first, last time.Duration
	for i := range walkers {
		d := <-finished
		if i == 0 || d < first {
			first = d
		}
		if d > last {
			last = d
		}
	}
	// Slots are 10ms apart, so five walkers span ~40ms. A thundering herd
	// finishes within a millisecond or two of each other.
	if spread := last - first; spread < 25*time.Millisecond {
		t.Fatalf("walkers finished within %v of each other, want slots spread ~40ms apart", spread)
	}
}

// Under sustained wait() load the balance never returns to zero, so a walker
// that polled for a non-negative balance starved until its job deadline. A
// reserving walker queues behind the load and finishes promptly.
func TestTokenBucketWaitDebtNotStarvedByWaiters(t *testing.T) {
	b := newTokenBucket(1000, nil) // burst of 100, then 1ms per token
	for range 100 {
		b.charge()
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b.wait(context.Background())
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()

	time.Sleep(20 * time.Millisecond) // let the waiters drive the balance negative
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := range 5 {
		if !b.waitDebt(ctx) {
			t.Fatalf("waitDebt %d starved under sustained wait load: %v", i, ctx.Err())
		}
	}
}

// refund must refill before adding and cap at the burst: after setRate lowers
// the burst, cancelled waiters' refunds must not leave the balance above it.
func TestTokenBucketRefundCapsAtBurst(t *testing.T) {
	current := time.Now()
	b := newTokenBucket(100, func() time.Time { return current }) // burst 10

	// Queue reservations, then lower the rate so the burst drops to 1.
	for range 20 {
		b.reserve()
	}
	b.setRate(10)
	// Time passes and every queued waiter is cancelled and refunds.
	current = current.Add(5 * time.Second)
	for range 20 {
		b.refund()
	}
	if b.tokens > b.burst {
		t.Fatalf("tokens = %v after refunds, want <= burst %v", b.tokens, b.burst)
	}
	// Only the burst is available immediately; the next caller must wait.
	if d := b.reserve(); d != 0 {
		t.Fatalf("first reserve waited %v, want 0 within burst", d)
	}
	if d := b.reserve(); d == 0 {
		t.Fatal("second reserve did not wait; refunds lifted the balance above the burst")
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
	results, err := q.WalkAll("1.3.6.1")
	if err != nil {
		t.Fatalf("WalkAll: %v", err)
	}
	// WalkAll collects PDUs through the paced Walk path, so the delegate
	// records a Walk root rather than a WalkAll call.
	if len(mock.walkRoots) != 1 {
		t.Fatal("WalkAll did not delegate")
	}
	if len(results) != 1 || results[0].Name != "1.3.6.1.1" {
		t.Fatalf("WalkAll collected %v, want the walk's PDU", results)
	}
	if results, err := q.BulkWalkAll("1.3.6.1"); err != nil || len(results) != 1 {
		t.Fatalf("BulkWalkAll = %v, %v; want one collected PDU", results, err)
	}
	if len(mock.bulkWalkRoots) != 1 {
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
	// One root from BulkWalkAll routing through BulkWalk, plus the direct
	// BulkWalk call above.
	if len(mock.bulkWalkRoots) != 2 {
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

// A walk must repay the OnSent debt between requests instead of dumping
// every GETNEXT/GETBULK back-to-back. The mock charges the bucket per PDU
// the way gosnmp's OnSent does per packet, so five PDUs at 100/s must take
// roughly five token intervals (50ms); without pacing it returns instantly.
func TestRateLimitedQuerierPacesWalks(t *testing.T) {
	t.Cleanup(func() { setSNMPPDURate(defaultSNMPPDURate) })
	setSNMPPDURate(100) // burst of 10, then 10ms per token

	// Drop the burst so every step of the walk runs under debt.
	snmpPDUs.mu.Lock()
	snmpPDUs.tokens = 0
	snmpPDUs.last = snmpPDUs.now()
	snmpPDUs.mu.Unlock()

	const pdus = 5
	mock := &mockSnmpQuerier{
		walkStepFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
			out := make([]gosnmp.SnmpPDU, pdus)
			for i := range out {
				out[i].Name = fmt.Sprintf("%s.%d", rootOid, i+1)
			}
			return out, nil
		},
		onWalkPDU: func() { snmpPDUs.charge() },
	}
	q := &rateLimitedQuerier{ctx: context.Background(), q: mock}

	start := time.Now()
	results, err := q.WalkAll("1.3.6.1")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WalkAll: %v", err)
	}
	if len(results) != pdus {
		t.Fatalf("WalkAll collected %d PDUs, want %d", len(results), pdus)
	}
	// Each paced step sleeps until the last send's token is repaid (~10ms at
	// 100/s); unpaced sends finish in microseconds.
	if elapsed < 40*time.Millisecond {
		t.Fatalf("walk of %d PDUs finished in %v; the limiter did not pace the requests", pdus, elapsed)
	}
}

// pacedWalkFn must surface a walkFn error without touching the bucket, and a
// cancelled ctx while repaying debt must end the walk.
func TestPacedWalkFnErrorAndCancel(t *testing.T) {
	t.Cleanup(func() { setSNMPPDURate(defaultSNMPPDURate) })

	mock := &mockSnmpQuerier{}
	q := &rateLimitedQuerier{ctx: context.Background(), q: mock}
	paced := q.pacedWalkFn(func(gosnmp.SnmpPDU) error { return errors.New("walkFn failed") })
	if err := paced(gosnmp.SnmpPDU{}); err == nil || err.Error() != "walkFn failed" {
		t.Fatalf("pacedWalkFn = %v, want walkFn error", err)
	}

	// With debt outstanding and a cancelled ctx, the wrapped fn returns the
	// ctx error instead of nil.
	setSNMPPDURate(1)
	snmpPDUs.charge()
	ctx, cancel := context.WithCancel(context.Background())
	q.ctx = ctx
	paced = q.pacedWalkFn(func(gosnmp.SnmpPDU) error { return nil })
	cancel()
	if err := paced(gosnmp.SnmpPDU{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pacedWalkFn = %v, want context.Canceled", err)
	}
}
