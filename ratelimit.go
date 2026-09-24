// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// defaultSNMPPDURate is the process-wide ceiling on SNMP request packets per
// second. It is deliberately conservative: a 100-device job push must not turn
// into tens of thousands of packets in a few seconds from one host.
const defaultSNMPPDURate = 200

// dispatchJitterMax bounds the random delay applied before a dispatched job
// starts executing, so a batch push does not start every job in the same
// instant. Tests may shrink it to keep dispatch synchronous.
var dispatchJitterMax = 50 * time.Millisecond

// tokenBucket paces work at a fixed rate. Tokens accrue continuously up to a
// small burst; callers that arrive faster than the rate reserve future tokens
// (the balance goes negative) and sleep off their debt, which keeps concurrent
// waiters ordered instead of thundering on each refill.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second; <= 0 disables limiting
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rate float64, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	b := &tokenBucket{now: now, last: now()}
	b.setRate(rate)
	b.tokens = b.burst
	return b
}

// setRate changes the limit. A rate <= 0 disables the bucket entirely.
func (b *tokenBucket) setRate(rate float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rate = rate
	// The burst covers a tenth of a second of traffic: enough to absorb timer
	// granularity, small enough that an idle agent cannot dump a second's
	// worth of PDUs the moment work resumes.
	b.burst = rate / 10
	if b.burst < 1 {
		b.burst = 1
	}
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// refillLocked accrues tokens for elapsed time. Caller holds b.mu.
func (b *tokenBucket) refillLocked(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// reserve consumes one token and reports how long the caller must wait before
// spending it. A zero return means the token was available immediately.
func (b *tokenBucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 {
		return 0
	}
	b.refillLocked(b.now())
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// charge consumes one token without waiting, letting the balance go negative.
// It is used where sleeping is unsafe (inside gosnmp's request deadline); the
// debt is paid off by settle before the next request.
func (b *tokenBucket) charge() {
	_ = b.reserve()
}

// settle blocks until the bucket's balance is non-negative — that is, until
// debt accumulated by charge has been refilled — or ctx is cancelled. It does
// not consume a token itself; the next charge pays for the next request.
func (b *tokenBucket) settle(ctx context.Context) bool {
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return true
	}
	b.refillLocked(b.now())
	var delay time.Duration
	if b.tokens < 0 {
		delay = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()

	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// snmpSentHook returns the gosnmp OnSent callback that charges every
// transmitted packet — including retries — against the bucket. It never
// sleeps: blocking inside OnSent would consume gosnmp's per-request deadline,
// so the debt is settled before the next request instead (see
// rateLimitedQuerier).
func snmpSentHook(b *tokenBucket) func(*gosnmp.GoSNMP) {
	return func(*gosnmp.GoSNMP) { b.charge() }
}

// rateLimitedQuerier settles the process-wide token bucket before each SNMP
// request, outside gosnmp's request deadline. Combined with the OnSent charge
// this paces real wire traffic at the configured rate.
type rateLimitedQuerier struct {
	ctx context.Context
	q   snmpQuerier
}

func (r *rateLimitedQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	snmpPDUs.settle(r.ctx)
	return r.q.Get(oids)
}

func (r *rateLimitedQuerier) WalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	snmpPDUs.settle(r.ctx)
	return r.q.WalkAll(rootOid)
}

func (r *rateLimitedQuerier) BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	snmpPDUs.settle(r.ctx)
	return r.q.BulkWalkAll(rootOid)
}

func (r *rateLimitedQuerier) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
	snmpPDUs.settle(r.ctx)
	return r.q.Walk(rootOid, walkFn)
}

func (r *rateLimitedQuerier) BulkWalk(rootOid string, walkFn gosnmp.WalkFunc) error {
	snmpPDUs.settle(r.ctx)
	return r.q.BulkWalk(rootOid, walkFn)
}

// snmpPDUs is the process-wide token bucket for outbound SNMP request packets.
// gosnmp invokes it through the connection's OnSent hook, so retries count
// against the same budget as first attempts.
var snmpPDUs = newTokenBucket(defaultSNMPPDURate, nil)

// setSNMPPDURate applies the configured packets-per-second ceiling. Zero
// disables rate limiting.
func setSNMPPDURate(rate uint) {
	snmpPDUs.setRate(float64(rate))
}

// dispatchJitter returns a random delay in [0, dispatchJitterMax).
func dispatchJitter() time.Duration {
	if dispatchJitterMax <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(dispatchJitterMax)))
}

// jitterDispatch sleeps delay to spread the start times of jobs pushed in one
// batch. It returns early when ctx is cancelled.
func jitterDispatch(ctx context.Context, delay time.Duration) {
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
