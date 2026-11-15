// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// TestExpandSnmpQueryOIDs covers the compact interface form: plain OIDs stay
// first, every column/index pair expands once, duplicates are dropped, and an
// empty side expands nothing.
func TestExpandSnmpQueryOIDs(t *testing.T) {
	query := &pb.SnmpQuery{
		Oids:       []string{"1.3.6.1.2.1.1.3.0"},
		OidColumns: []string{"1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.1."},
		OidIndexes: []uint32{1, 10101},
	}
	got := expandSnmpQueryOIDs(query)
	want := []string{
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.2.1.2.2.1.1.1",
		"1.3.6.1.2.1.2.2.1.1.10101",
	}
	if len(got) != len(want) {
		t.Fatalf("expanded %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expanded[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	empty := expandSnmpQueryOIDs(&pb.SnmpQuery{OidColumns: []string{"1.2.3"}})
	if len(empty) != 0 {
		t.Fatalf("columns without indexes expanded to %v", empty)
	}
}

// TestInventoryFullSyncAppliesAtomically verifies that chunks of a full sync
// are buffered until the last one lands, then replace the schedule once.
func TestInventoryFullSyncAppliesAtomically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := &jobPools{
		snmp:     newWorkerPool(1),
		mikrotik: newWorkerPool(1),
		ping:     newWorkerPool(1),
		checks:   newWorkerPool(1),
		backup:   newWorkerPool(1),
		notices:  make(chan outbound, 1),
		targets:  &targetGates{},
	}
	results := newResultQueueForAgent(ctx, 8)
	scheduler := newRecurringScheduler(ctx, realScheduleClock{})
	pools.scheduler = scheduler
	defer scheduler.cancelAll()

	job := &pb.AgentJob{JobId: "job-1", IntervalSeconds: 300}
	first := &pb.AgentInventoryUpdate{
		Revision: 7, FullSync: true, ChunkIndex: 1, ChunkCount: 2,
		Upserts: []*pb.AgentJob{job},
	}
	second := &pb.AgentInventoryUpdate{
		Revision: 7, FullSync: true, ChunkIndex: 2, ChunkCount: 2,
		RemoveJobIds: []string{"stale"},
	}

	applyInventoryUpdate(pools, scheduler, first, results)
	if got := len(scheduler.jobs); got != 0 {
		t.Fatalf("partial full sync applied %d jobs", got)
	}
	if got := pools.appliedRevision.Load(); got != 0 {
		t.Fatalf("partial full sync advanced revision to %d", got)
	}

	applyInventoryUpdate(pools, scheduler, second, results)
	if got := len(scheduler.jobs); got != 1 {
		t.Fatalf("completed full sync scheduled %d jobs, want 1", got)
	}
	if got := pools.appliedRevision.Load(); got != 7 {
		t.Fatalf("applied revision = %d, want 7", got)
	}

	// An older incremental change is ignored once reconciliation lands.
	stale := &pb.AgentInventoryUpdate{
		Revision: 6, Upserts: []*pb.AgentJob{{JobId: "stale-job", IntervalSeconds: 60}},
	}
	applyInventoryUpdate(pools, scheduler, stale, results)
	if got := len(scheduler.jobs); got != 1 {
		t.Fatalf("stale update changed the schedule to %d jobs", got)
	}
}

// TestInventoryIncrementalUpsertPreservesUnchanged verifies a per-device
// update replaces only the named assignment and keeps the rest.
func TestInventoryIncrementalUpsertPreservesUnchanged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := &jobPools{
		snmp:     newWorkerPool(1),
		mikrotik: newWorkerPool(1),
		ping:     newWorkerPool(1),
		checks:   newWorkerPool(1),
		backup:   newWorkerPool(1),
		notices:  make(chan outbound, 1),
		targets:  &targetGates{},
	}
	results := newResultQueueForAgent(ctx, 8)
	scheduler := newRecurringScheduler(ctx, realScheduleClock{})
	pools.scheduler = scheduler
	defer scheduler.cancelAll()

	full := &pb.AgentInventoryUpdate{
		Revision: 1, FullSync: true, ChunkIndex: 1, ChunkCount: 1,
		Upserts: []*pb.AgentJob{
			{JobId: "keep", IntervalSeconds: 60},
			{JobId: "change", IntervalSeconds: 60},
		},
	}
	applyInventoryUpdate(pools, scheduler, full, results)

	update := &pb.AgentInventoryUpdate{
		Revision:     2,
		Upserts:      []*pb.AgentJob{{JobId: "change", IntervalSeconds: 120}},
		RemoveJobIds: []string{"keep"},
	}
	applyInventoryUpdate(pools, scheduler, update, results)

	if got := len(scheduler.jobs); got != 1 {
		t.Fatalf("scheduled jobs = %d, want 1", got)
	}
	entry := scheduler.jobs["change"]
	if entry == nil || entry.spec.interval != 120*time.Second {
		t.Fatalf("changed assignment interval = %v", entry)
	}
	if pools.appliedRevision.Load() != 2 {
		t.Fatalf("applied revision = %d, want 2", pools.appliedRevision.Load())
	}
}

func TestInventoryCapacityUsesMeasuredFootprint(t *testing.T) {
	before := inventoryAvgDeviceBytes.Load()
	defer inventoryAvgDeviceBytes.Store(before)
	noteInventoryFootprint(10, 1000)
	if got := inventoryAvgDeviceBytes.Load(); got != 100 {
		t.Fatalf("measured per-device bytes = %d, want 100", got)
	}
	want := uint64(maxDecodedJobPayloadBytes) / 100
	if got := inventoryCapacityDevices(); got != want {
		t.Fatalf("capacity = %d, want %d", got, want)
	}
}
