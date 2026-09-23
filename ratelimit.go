// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
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

// reserve consumes one token and reports how long the caller must wait before
// spending it. A zero return means the token was available immediately.
func (b *tokenBucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 {
		return 0
	}
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// wait blocks until one token is available or ctx is cancelled.
func (b *tokenBucket) wait(ctx context.Context) bool {
	delay := b.reserve()
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

// jitterDispatch sleeps a random sub-max duration to spread the start times of
// jobs pushed in one batch. It returns early when ctx is cancelled.
func jitterDispatch(ctx context.Context) {
	delay := dispatchJitter()
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
