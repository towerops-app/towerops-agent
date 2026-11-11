// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"
)

// wait blocks until one token is available, including debt left by charge,
// or ctx is cancelled. It consumes the token. Only tests call it: production
// paces SNMP through waitDebt.
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

// setRate settles the time elapsed under the old rate before switching, so a
// rate change does not credit the idle period at the new rate.
func TestTokenBucketSetRateRefillsAtOldRateFirst(t *testing.T) {
	current := time.Unix(0, 0)
	b := newTokenBucket(10, func() time.Time { return current }) // burst 1
	b.tokens = 0

	current = current.Add(50 * time.Millisecond) // 0.5 tokens at 10/s
	b.setRate(1000)                              // burst 100

	if b.tokens != 0.5 {
		t.Fatalf("tokens = %v after setRate, want 0.5 accrued at the old rate", b.tokens)
	}
}
