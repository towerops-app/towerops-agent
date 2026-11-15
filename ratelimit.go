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

// defaultSNMPDevicePDURate is the default per-device ceiling on SNMP request
// packets per second. It is the safety limit for one misbehaving device, not
// the fleet limit: a 25-packet poll stays well under 50 packets/s.
const defaultSNMPDevicePDURate = 50

// defaultSNMPPDURate is the process-wide ceiling on SNMP request packets per
// second. Zero disables it: the per-device limiter and scheduler admission
// bound a misbehaving device, so a fleet ceiling would only cap healthy
// throughput (a 3,000-device inventory needs well over 1,000 packets/s).
const defaultSNMPPDURate = 0

// snmpRateLimitWait returns the cumulative limiter wait. Reported, never reset.
func snmpRateLimitWait() time.Duration {
	return time.Duration(processMetrics.rateLimitWaitNs.Load())
}

func snmpRateLimitWaitMillis() uint64 {
	return uint64(snmpRateLimitWait().Milliseconds())
}

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

// setRate changes the limit. A rate <= 0 disables the bucket entirely. Time
// elapsed since the last refill accrues at the old rate first; otherwise the
// next refill would credit that whole span at the new rate.
func (b *tokenBucket) setRate(rate float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked(b.now())
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
// debt is paid off by waitDebt before the next request.
func (b *tokenBucket) charge() {
	_ = b.reserve()
}

// refund returns a token whose reservation was abandoned — the caller never
// transmitted — so a cancelled wait does not leave debt behind for the next
// caller to sleep off. It refills first and caps at the burst, so refunds
// after setRate lowered the burst (or after an idle spell) cannot lift the
// balance above it and let the next callers exceed the configured burst.
func (b *tokenBucket) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 {
		return
	}
	b.refillLocked(b.now())
	b.tokens++
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// waitDebt blocks until the bucket can afford one more send, or ctx is
// cancelled. It exists to pace a sequence of requests whose sends are
// already charged by OnSent — rateLimitedQuerier calls it before every
// Get, GetNext and GetBulk so pacing happens outside gosnmp's request
// deadline.
//
// It reserves a token, so concurrent walkers get distinct, ordered slots
// instead of polling for a non-negative balance —
// which under sustained load never arrives, and when it does wakes every
// walker at once. Once its slot comes up it hands the token back, so the
// OnSent charge for the send that follows is the only token the send costs.
func (b *tokenBucket) waitDebt(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	delay := b.reserve()
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			b.refund()
			return false
		case <-timer.C:
		}
	}
	b.refund()
	return ctx.Err() == nil
}

// waitSNMPBuckets waits for one send slot from the global ceiling first and
// the device's own limiter second. It measures only real blocking; an
// immediate token costs nothing. The reservation is refunded, so the OnSent
// charge that follows the actual transmission is the only token the send costs.
func waitSNMPBuckets(ctx context.Context, device *tokenBucket) bool {
	if ctx.Err() != nil {
		return false
	}
	started := time.Now()
	if !snmpPDUs.waitDebt(ctx) || (device != nil && !device.waitDebt(ctx)) {
		return false
	}
	if waited := time.Since(started); waited > 0 {
		processMetrics.rateLimitWaitNs.Add(uint64(waited.Nanoseconds()))
	}
	return true
}

// snmpSentHook returns the gosnmp OnSent callback that charges every
// transmitted packet — including retries — against the global bucket. It never
// sleeps: blocking inside OnSent would consume gosnmp's per-request deadline,
// so the debt is paid by waitDebt before the next request
// instead (see rateLimitedQuerier).
func snmpSentHook(b *tokenBucket) func(*gosnmp.GoSNMP) {
	return func(*gosnmp.GoSNMP) { b.charge() }
}

// snmpDeviceSentHook charges a transmitted packet against the global ceiling
// and the owning device's per-device limit.
func snmpDeviceSentHook(device *tokenBucket) func(*gosnmp.GoSNMP) {
	return func(*gosnmp.GoSNMP) {
		snmpPDUs.charge()
		if device != nil {
			device.charge()
		}
	}
}

// rateLimitedQuerier waits for a send slot before each SNMP request, outside
// gosnmp's request deadline. Pacing happens once per outgoing request — a
// 25-varbind GETBULK response costs one slot, not twenty-five — and waitDebt
// returns the reservation so OnSent alone charges transmitted packets,
// including retries; unsent requests cost nothing. The walk loop in snmp.go
// drives GetNext/GetBulk through these methods, so every request of a walk
// is paced and no sleep trails the last response. The global bucket defaults
// to unlimited; device is the per-device safety limit.
type rateLimitedQuerier struct {
	ctx    context.Context
	q      snmpQuerier
	device *tokenBucket
	cached bool
	// networkObserver sees the delegated request only: limiter waits must
	// not inflate RTT-based timeout adaptation.
	networkObserver func(elapsed time.Duration, err error)
	// respondedFn reports the owning job's response observation for B5.
	respondedFn func() bool
}

// responded implements snmpResponseObserver on behalf of the job wrapper.
func (r *rateLimitedQuerier) responded() bool {
	return r.respondedFn != nil && r.respondedFn()
}

func (r *rateLimitedQuerier) observeNetwork(started time.Time, err error) {
	if r.networkObserver != nil {
		r.networkObserver(time.Since(started), err)
	}
}

func (r *rateLimitedQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if !waitSNMPBuckets(r.ctx, r.device) {
		return nil, context.Canceled
	}
	started := time.Now()
	packet, err := r.q.Get(oids)
	r.observeNetwork(started, err)
	return packet, err
}

func (r *rateLimitedQuerier) GetNext(oids []string) (*gosnmp.SnmpPacket, error) {
	if !waitSNMPBuckets(r.ctx, r.device) {
		return nil, context.Canceled
	}
	started := time.Now()
	packet, err := r.q.GetNext(oids)
	r.observeNetwork(started, err)
	return packet, err
}

func (r *rateLimitedQuerier) GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (*gosnmp.SnmpPacket, error) {
	if !waitSNMPBuckets(r.ctx, r.device) {
		return nil, context.Canceled
	}
	started := time.Now()
	packet, err := r.q.GetBulk(oids, nonRepeaters, maxRepetitions)
	r.observeNetwork(started, err)
	return packet, err
}

// snmpPDUs is the process-wide token bucket for outbound SNMP request packets.
// gosnmp invokes it through the connection's OnSent hook, so retries count
// against the same budget as first attempts.
var snmpPDUs = newTokenBucket(defaultSNMPPDURate, nil)

// setSNMPPDURate applies the configured packets-per-second ceiling. Zero
// disables the global ceiling; the per-device limiter remains active.
func setSNMPPDURate(rate uint) {
	snmpPDUs.setRate(float64(rate))
}

// setSNMPDevicePDURate applies the per-device packets-per-second ceiling to
// existing and future device state. Zero disables a device's limiter too.
func setSNMPDevicePDURate(rate uint) {
	defaultSNMPEngine.setDeviceRate(float64(rate))
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
