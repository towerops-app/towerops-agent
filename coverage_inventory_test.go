// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

func TestExpandSnmpQueryOIDsGuards(t *testing.T) {
	if got := expandSnmpQueryOIDs(nil); got != nil {
		t.Errorf("nil query = %v", got)
	}
	q := &pb.SnmpQuery{Oids: []string{"1.3"}, OidColumns: []string{"1.3.6"}}
	if got := expandSnmpQueryOIDs(q); len(got) != 1 || got[0] != "1.3" {
		t.Errorf("columns without indexes must return oids: %v", got)
	}
	q2 := &pb.SnmpQuery{OidIndexes: []uint32{1}}
	if got := expandSnmpQueryOIDs(q2); len(got) != 0 {
		t.Errorf("indexes without columns must return oids: %v", got)
	}
	q3 := &pb.SnmpQuery{
		OidColumns: []string{"", "1.3.6."},
		OidIndexes: []uint32{0, 5},
	}
	if got := expandSnmpQueryOIDs(q3); len(got) != 1 || got[0] != "1.3.6.5" {
		t.Errorf("expansion = %v", got)
	}
}

func TestExpandJobQueriesGuards(t *testing.T) {
	expandJobQueries(nil)
	job := &pb.AgentJob{Queries: []*pb.SnmpQuery{nil, {Oids: []string{"1.3"}}}}
	expandJobQueries(job) // nil and unexpanded queries skipped
	if job.Queries[1].Oids[0] != "1.3" {
		t.Error("plain query must pass through")
	}
}

func TestInventoryAssemblerGuards(t *testing.T) {
	a := newInventoryAssembler()
	// Duplicate chunk index is a no-op success, not a restart.
	u := &pb.AgentInventoryUpdate{Revision: 1, ChunkIndex: 1, ChunkCount: 2}
	if !a.start(u) {
		t.Fatal("first chunk must start")
	}
	if !a.start(u) {
		t.Fatal("duplicate chunk must be a no-op true")
	}
	// A different revision resets the assembly.
	v := &pb.AgentInventoryUpdate{Revision: 2, ChunkIndex: 1, ChunkCount: 1}
	if !a.start(v) {
		t.Fatal("new revision must restart cleanly")
	}
	if a.revision != 2 {
		t.Errorf("revision = %d", a.revision)
	}
	if !a.complete() {
		t.Fatal("single-chunk sync must complete")
	}

	// The byte bound rejects an oversized assembly and reports rejection.
	pools := &jobPools{notices: make(chan outbound, 1), targets: &targetGates{}}
	results := newResultQueueForAgent(context.Background(), 8)
	big := &pb.AgentInventoryUpdate{
		Revision: 1, FullSync: true, ChunkIndex: 1, ChunkCount: 2,
		Upserts: []*pb.AgentJob{{
			JobId:           "huge",
			IntervalSeconds: 300,
			SnmpDevice:      &pb.SnmpDevice{Ip: strings.Repeat("9", 70<<20)},
		}},
	}
	if assembler := poolsInventoryAssembler(pools); assembler.start(big) {
		t.Fatal("70 MB chunk must trip the 64 MB assembly bound")
	}
	releaseInventoryAssembler(pools)
	_ = results
}

func TestApplyInventoryUpdateGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler := newRecurringScheduler(ctx, realScheduleClock{})
	defer scheduler.cancelAll()
	results := newResultQueueForAgent(ctx, 8)

	applyInventoryUpdate(nil, scheduler, &pb.AgentInventoryUpdate{}, results)
	pools := &jobPools{notices: make(chan outbound, 1), targets: &targetGates{}}
	applyInventoryUpdate(pools, nil, &pb.AgentInventoryUpdate{}, results)

	// FullSync routes to the chunk assembler; the memory-bound refusal path
	// reports a rejection result.
	oversized := &pb.AgentInventoryUpdate{
		Revision: 1, FullSync: true, ChunkIndex: 1, ChunkCount: 2,
		Upserts: []*pb.AgentJob{{
			JobId:           "huge",
			IntervalSeconds: 300,
			SnmpDevice:      &pb.SnmpDevice{Ip: strings.Repeat("9", 70<<20)},
		}},
	}
	applyInventoryUpdate(pools, scheduler, oversized, results)
	if got, _ := pools.rejectedInventory.Load().(string); got != "inventory_update" {
		t.Errorf("rejectedInventory = %q", got)
	}
	releaseInventoryAssembler(pools)
}

func TestApplyIncrementalUpdateMerge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)
	scheduler := pools.scheduler
	results := newResultQueueForAgent(ctx, 8)

	update := &pb.AgentInventoryUpdate{
		Revision: 9,
		Upserts: []*pb.AgentJob{
			nil, // nil entries are filtered downstream
			{JobId: "job-a", IntervalSeconds: 60},
		},
		UpsertChecks: []*pb.Check{{Id: "check-a", IntervalSeconds: 60}},
		RemoveJobIds: []string{"ghost"},
	}
	applyInventoryUpdate(pools, scheduler, update, results)
	if got := len(scheduler.jobs); got != 1 {
		t.Errorf("jobs = %d", got)
	}
	if got := len(scheduler.checks); got != 1 {
		t.Errorf("checks = %d", got)
	}
	if got := pools.appliedRevision.Load(); got != 9 {
		t.Errorf("revision = %d", got)
	}
}

func TestApplySNMPConcurrencySizingGuards(t *testing.T) {
	applySNMPConcurrencySizing(nil, 5)
	pools := &jobPools{}
	applySNMPConcurrencySizing(pools, 5) // nil snmp pool
	pools = &jobPools{snmp: newWorkerPool(1)}
	defer pools.snmp.stop()
	applySNMPConcurrencySizing(pools, 0) // zero count ignored
}

func TestIsInventoryEvent(t *testing.T) {
	s := &session{}
	if !s.isInventoryEvent("jobs") || !s.isInventoryEvent("check_jobs") {
		t.Error("jobs/check_jobs must route to the decoder")
	}
	if s.isInventoryEvent("inventory_update") {
		t.Error("inventory_update needs the capability flag")
	}
	if s.isInventoryEvent("result") {
		t.Error("results must not route to the decoder")
	}
	s.inventoryUpdates = true
	if !s.isInventoryEvent("inventory_update") {
		t.Error("capable session must route inventory_update")
	}
}

func TestStartInventoryDecoderIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{ctx: ctx}
	s.startInventoryDecoder()
	if s.inventoryWork == nil || s.inventoryResult == nil {
		t.Fatal("decoder channels not created")
	}
	first := s.inventoryWork
	s.startInventoryDecoder() // second call is a no-op
	if s.inventoryWork != first {
		t.Error("decoder restarted")
	}
	close(s.inventoryWork)
}

func TestInventoryDecodeCompatibilityPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)
	s := &session{ctx: ctx, jobCtx: ctx, topic: "agent:t", pools: pools, results: newResultQueue(4)}
	msg := channelMsg{Topic: "agent:t", Event: "jobs", Payload: json.RawMessage(`{"binary":""}`)}
	// The loop's compatibility path runs the synchronous handler when a
	// session has no decoder goroutine.
	end, err := handleMessage(s.jobCtx, msg, s.topic, pools, s.results)
	if err != nil {
		t.Errorf("compat path: %v", err)
	}
	_ = end
}

func TestDecodeInventoryRequest(t *testing.T) {
	// Undecodable jobs payload → decoded stays false.
	if r := decodeInventoryRequest(inventoryDecodeRequest{event: "jobs", payload: json.RawMessage(`bad`)}); r.decoded {
		t.Error("bad jobs payload must not decode")
	}
	// Valid jobs payload.
	list := &pb.AgentJobList{Revision: 1}
	raw, _ := proto.Marshal(list)
	payload, _ := json.Marshal(map[string]string{"binary": base64enc(raw)})
	if r := decodeInventoryRequest(inventoryDecodeRequest{event: "jobs", payload: payload}); !r.decoded || r.jobs == nil {
		t.Error("jobs payload must decode")
	}
	// Valid check_jobs payload.
	cl := &pb.CheckList{}
	craw, _ := proto.Marshal(cl)
	cpayload, _ := json.Marshal(map[string]string{"binary": base64enc(craw)})
	if r := decodeInventoryRequest(inventoryDecodeRequest{event: "check_jobs", payload: cpayload}); !r.decoded || r.checks == nil {
		t.Error("check_jobs payload must decode")
	}
	if r := decodeInventoryRequest(inventoryDecodeRequest{event: "check_jobs", payload: json.RawMessage(`bad`)}); r.decoded {
		t.Error("bad check_jobs payload must not decode")
	}
	// inventory_update with compact columns expands them during decode.
	up := &pb.AgentInventoryUpdate{
		Revision: 3,
		Upserts: []*pb.AgentJob{{
			JobId:           "j1",
			IntervalSeconds: 60,
			Queries: []*pb.SnmpQuery{{
				OidColumns: []string{"1.3.6.1.2.1.2.2.1.10"},
				OidIndexes: []uint32{1},
			}},
		}},
	}
	uraw, _ := proto.Marshal(up)
	if r := decodeInventoryRequest(inventoryDecodeRequest{
		event: "inventory_update", rawProto: true, payload: uraw,
	}); !r.decoded || r.update == nil {
		t.Fatal("inventory_update must decode")
	} else if got := r.update.Upserts[0].Queries[0].Oids; len(got) != 1 {
		t.Errorf("expanded oids = %v", got)
	}
	// Unknown event decodes to nothing.
	if r := decodeInventoryRequest(inventoryDecodeRequest{event: "other"}); r.decoded {
		t.Error("unknown event must not decode")
	}
}

func TestApplyInventoryDecode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pools := testPools(t)

	t.Run("undecoded result rejects the frame", func(t *testing.T) {
		s := &session{ctx: ctx, jobCtx: ctx, results: newResultQueue(8), pools: pools}
		s.applyInventoryDecode(inventoryDecodeResult{event: "jobs"}, pools, s.results)
		if got, _ := pools.rejectedInventory.Load().(string); got != "jobs" {
			t.Errorf("rejectedInventory = %q", got)
		}
	})

	t.Run("jobs dispatches to applyJobList", func(t *testing.T) {
		s := &session{ctx: ctx, jobCtx: ctx, results: newResultQueue(8), pools: pools, scheduler: pools.scheduler}
		list := &pb.AgentJobList{Revision: 11}
		s.applyInventoryDecode(inventoryDecodeResult{event: "jobs", jobs: list, decoded: true}, pools, s.results)
		// Empty jobs with only one-shots is not authoritative; no revision.
	})

	t.Run("check_jobs dispatches to applyCheckList", func(t *testing.T) {
		s := &session{ctx: ctx, jobCtx: ctx, results: newResultQueue(8), pools: pools, scheduler: pools.scheduler}
		list := &pb.CheckList{}
		s.applyInventoryDecode(inventoryDecodeResult{event: "check_jobs", checks: list, decoded: true}, pools, s.results)
	})

	t.Run("inventory_update without poller applies directly", func(t *testing.T) {
		s := &session{ctx: ctx, jobCtx: ctx, results: newResultQueue(8), pools: pools, scheduler: pools.scheduler}
		update := &pb.AgentInventoryUpdate{
			Revision: 12,
			Upserts:  []*pb.AgentJob{{JobId: "j-x", IntervalSeconds: 60}},
		}
		s.applyInventoryDecode(inventoryDecodeResult{
			event: "inventory_update", update: update, decoded: true,
		}, pools, s.results)
		if got := len(pools.scheduler.jobs); got != 1 {
			t.Errorf("jobs = %d", got)
		}
	})
}

func base64enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
