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
// debt is paid off by wait or waitDebt before the next request.
func (b *tokenBucket) charge() {
	_ = b.reserve()
}

// refund returns a token whose reservation was abandoned — the caller never
// transmitted — so a cancelled wait does not leave debt behind for the next
// caller to sleep off.
func (b *tokenBucket) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens++
}

// wait blocks until one token is available — including paying off debt
// accumulated by charge — or ctx is cancelled. It consumes the token, so the
// caller may transmit immediately after it returns.
func (b *tokenBucket) wait(ctx context.Context) bool {
	delay := b.reserve()
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		b.refund()
		return false
	case <-timer.C:
		return true
	}
}

// waitDebt blocks until the bucket's outstanding debt (a negative balance
// accumulated by charge) is repaid by the refiller, or ctx is cancelled.
// Unlike wait it does not consume a token: it exists to pace a sequence of
// requests where each send is already charged by OnSent, e.g. inside a
// gosnmp walkFn between one response and the next request.
func (b *tokenBucket) waitDebt(ctx context.Context) bool {
	for {
		b.mu.Lock()
		if b.rate <= 0 {
			b.mu.Unlock()
			return true
		}
		b.refillLocked(b.now())
		if b.tokens >= 0 {
			b.mu.Unlock()
			return ctx.Err() == nil
		}
		delay := time.Duration(-b.tokens / b.rate * float64(time.Second))
		b.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

// snmpSentHook returns the gosnmp OnSent callback that charges every
// transmitted packet — including retries — against the bucket. It never
// sleeps: blocking inside OnSent would consume gosnmp's per-request deadline,
// so the debt is paid by the next wait or waitDebt before the next request
// instead (see rateLimitedQuerier).
func snmpSentHook(b *tokenBucket) func(*gosnmp.GoSNMP) {
	return func(*gosnmp.GoSNMP) { b.charge() }
}

// rateLimitedQuerier takes a token from the process-wide bucket before each
// SNMP request, so pacing happens before transmit and outside gosnmp's
// request deadline. Combined with the OnSent charge this bounds real wire
// traffic at the configured rate.
type rateLimitedQuerier struct {
	ctx context.Context
	q   snmpQuerier
}

func (r *rateLimitedQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if !snmpPDUs.wait(r.ctx) {
		return nil, r.ctx.Err()
	}
	return r.q.Get(oids)
}

// pacedWalkFn wraps a gosnmp WalkFunc so the debt charged by OnSent for the
// request just answered is repaid before gosnmp sends the next GETNEXT or
// GETBULK. walkFn runs after each response and before the next request, so
// the sleep never consumes gosnmp's per-request deadline — without it a walk
// sends every packet back-to-back and the wire rate ignores the limiter.
func (r *rateLimitedQuerier) pacedWalkFn(walkFn gosnmp.WalkFunc) gosnmp.WalkFunc {
	return func(pdu gosnmp.SnmpPDU) error {
		if err := walkFn(pdu); err != nil {
			return err
		}
		if !snmpPDUs.waitDebt(r.ctx) {
			return r.ctx.Err()
		}
		return nil
	}
}

func (r *rateLimitedQuerier) WalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	var results []gosnmp.SnmpPDU
	err := r.Walk(rootOid, func(pdu gosnmp.SnmpPDU) error {
		results = append(results, pdu)
		return nil
	})
	return results, err
}

func (r *rateLimitedQuerier) BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	var results []gosnmp.SnmpPDU
	err := r.BulkWalk(rootOid, func(pdu gosnmp.SnmpPDU) error {
		results = append(results, pdu)
		return nil
	})
	return results, err
}

func (r *rateLimitedQuerier) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
	if !snmpPDUs.wait(r.ctx) {
		return r.ctx.Err()
	}
	return r.q.Walk(rootOid, r.pacedWalkFn(walkFn))
}

func (r *rateLimitedQuerier) BulkWalk(rootOid string, walkFn gosnmp.WalkFunc) error {
	if !snmpPDUs.wait(r.ctx) {
		return r.ctx.Err()
	}
	return r.q.BulkWalk(rootOid, r.pacedWalkFn(walkFn))
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
