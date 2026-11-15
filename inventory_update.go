// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// Capability tokens advertised in the join payload and on every heartbeat.
const (
	capabilityInventoryUpdate   = "inventory_update_v1"
	capabilityResultBatch       = "result_batch_v1"
	capabilityResultAck         = "result_ack_v1"
	capabilityInventoryCapacity = "inventory_capacity"
)

// inventoryCapabilities is the canonical agent capability list.
func inventoryCapabilities() []string {
	return []string{
		capabilityInventoryUpdate,
		capabilityResultBatch,
		capabilityResultAck,
		capabilityInventoryCapacity,
	}
}

// estimatedInventoryDeviceBytes is the initial per-device inventory cost used
// before the first authoritative inventory updates the measurement.
const estimatedInventoryDeviceBytes = 9048

// maxInventoryAssemblyBytes bounds the decoded payloads held while chunks of
// a full sync accumulate. The target inventory (27 MB) fits with room for
// growth; a larger sync is refused whole instead of silently pinning memory.
const maxInventoryAssemblyBytes = 64 << 20

// expandSnmpQueryOIDs expands the compact interface form: every column root
// crossed with every index (`column.index`). The plain `oids` list is always
// preserved ahead of the expansion, and duplicates are dropped in order.
func expandSnmpQueryOIDs(query *pb.SnmpQuery) []string {
	if query == nil {
		return nil
	}
	if len(query.OidColumns) == 0 || len(query.OidIndexes) == 0 {
		return query.Oids
	}
	expanded := make([]string, 0,
		len(query.Oids)+len(query.OidColumns)*len(query.OidIndexes))
	seen := make(map[string]struct{}, len(query.OidColumns)*len(query.OidIndexes))
	appendOID := func(oid string) {
		if oid == "" {
			return
		}
		if _, dup := seen[oid]; dup {
			return
		}
		seen[oid] = struct{}{}
		expanded = append(expanded, oid)
	}
	for _, oid := range query.Oids {
		appendOID(oid)
	}
	for _, column := range query.OidColumns {
		column = strings.TrimSuffix(column, ".")
		if column == "" {
			continue
		}
		for _, index := range query.OidIndexes {
			if index == 0 {
				continue
			}
			appendOID(column + "." + strconv.FormatUint(uint64(index), 10))
		}
	}
	return expanded
}

// expandJobQueries normalizes a decoded job's queries in place, so every
// consumer (SNMP engine, fingerprints, debug logs) sees full OIDs only.
func expandJobQueries(job *pb.AgentJob) {
	if job == nil {
		return
	}
	for _, query := range job.Queries {
		if query == nil || len(query.OidColumns) == 0 || len(query.OidIndexes) == 0 {
			continue
		}
		query.Oids = expandSnmpQueryOIDs(query)
		query.OidColumns = nil
		query.OidIndexes = nil
	}
}

// expandInventoryJobs normalizes every job payload of an update.
func expandInventoryJobs(jobs []*pb.AgentJob) {
	for _, job := range jobs {
		expandJobQueries(job)
	}
}

// inventoryAssembler accumulates chunks of one full sync and applies them
// atomically: nothing reaches the scheduler until every chunk_index arrived.
type inventoryAssembler struct {
	mu           sync.Mutex
	revision     uint64
	chunkCount   uint32
	seen         map[uint32]struct{}
	bytes        int
	upserts      map[uint32][]*pb.AgentJob
	upsertChecks map[uint32][]*pb.Check
	removeJobs   map[uint32][]string
	removeChecks map[uint32][]string
}

func newInventoryAssembler() *inventoryAssembler {
	return &inventoryAssembler{
		upserts:      make(map[uint32][]*pb.AgentJob),
		upsertChecks: make(map[uint32][]*pb.Check),
		removeJobs:   make(map[uint32][]string),
		removeChecks: make(map[uint32][]string),
	}
}

// reset discards any assembly for an older revision and starts one for this
// revision. Returns false when the chunk budget is exhausted.
func (a *inventoryAssembler) start(update *pb.AgentInventoryUpdate) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revision != update.Revision || a.chunkCount != update.ChunkCount {
		a.revision = update.Revision
		a.chunkCount = update.ChunkCount
		a.seen = make(map[uint32]struct{})
		a.bytes = 0
		clear(a.upserts)
		clear(a.upsertChecks)
		clear(a.removeJobs)
		clear(a.removeChecks)
	}
	if _, duplicate := a.seen[update.ChunkIndex]; duplicate {
		return true
	}
	size := proto.Size(update)
	if a.bytes+size > maxInventoryAssemblyBytes {
		slog.Error("inventory full sync exceeds assembly memory bound",
			"revision", update.Revision,
			"bytes", a.bytes+size,
			"max", maxInventoryAssemblyBytes)
		return false
	}
	a.bytes += size
	a.seen[update.ChunkIndex] = struct{}{}
	a.upserts[update.ChunkIndex] = update.Upserts
	a.upsertChecks[update.ChunkIndex] = update.UpsertChecks
	a.removeJobs[update.ChunkIndex] = update.RemoveJobIds
	a.removeChecks[update.ChunkIndex] = update.RemoveCheckIds
	return true
}

// complete reports whether every chunk of the assembly has arrived.
func (a *inventoryAssembler) complete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen) == int(a.chunkCount)
}

// merged returns the union of every chunk, ordered by chunk index, and clears
// the assembly. Called only when complete.
func (a *inventoryAssembler) merged() (
	jobs []*pb.AgentJob,
	checks []*pb.Check,
	removeJobs []string,
	removeChecks []string,
	encodedBytes int,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	indexes := make([]uint32, 0, len(a.upserts))
	for index := range a.upserts {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	for _, index := range indexes {
		jobs = append(jobs, a.upserts[index]...)
		checks = append(checks, a.upsertChecks[index]...)
		removeJobs = append(removeJobs, a.removeJobs[index]...)
		removeChecks = append(removeChecks, a.removeChecks[index]...)
		encodedBytes += proto.Size(&pb.AgentInventoryUpdate{
			Upserts:        a.upserts[index],
			UpsertChecks:   a.upsertChecks[index],
			RemoveJobIds:   a.removeJobs[index],
			RemoveCheckIds: a.removeChecks[index],
		})
	}
	a.revision = 0
	a.chunkCount = 0
	a.seen = nil
	a.bytes = 0
	clear(a.upserts)
	clear(a.upsertChecks)
	clear(a.removeJobs)
	clear(a.removeChecks)
	return jobs, checks, removeJobs, removeChecks, encodedBytes
}

// applyInventoryUpdate applies one decoded AgentInventoryUpdate to the
// process poller's scheduler. Chunks of a full sync are buffered until the
// last chunk lands, then replace the whole schedule in one call.
func applyInventoryUpdate(
	pools *jobPools,
	scheduler *recurringScheduler,
	update *pb.AgentInventoryUpdate,
	out *resultQueue,
) {
	if pools == nil || scheduler == nil {
		return
	}
	if update.FullSync {
		applyFullSyncChunk(pools, scheduler, update, out)
		return
	}
	applyIncrementalUpdate(pools, scheduler, update, out)
}

func applyFullSyncChunk(
	pools *jobPools,
	scheduler *recurringScheduler,
	update *pb.AgentInventoryUpdate,
	out *resultQueue,
) {
	assembler := poolsInventoryAssembler(pools)
	chunkCount := update.ChunkCount
	if chunkCount == 0 {
		chunkCount = 1
	}
	update.ChunkCount = chunkCount
	if update.ChunkIndex == 0 {
		update.ChunkIndex = 1
	}
	if !assembler.start(update) {
		pools.rejectInventory("inventory_update")
		reportInventoryRejection(out.agentCtx, out, "inventory_update",
			"Rejected inventory full sync: assembly memory bound exceeded")
		return
	}
	if !assembler.complete() {
		return
	}
	jobs, checks, _, _, encodedBytes := assembler.merged()
	expandInventoryJobs(jobs)
	expandInventoryChecks(checks)

	// An authoritative full sync with no entries is still authoritative.
	scheduler.replaceJobs(jobs, pools, out)
	scheduler.replaceChecks(checks, pools, out)
	applySNMPConcurrencySizing(pools, len(jobs))
	noteInventoryFootprint(len(jobs)+len(checks), encodedBytes)
	pools.applyInventoryRevision("inventory_update", update.Revision)
	slog.Info("applied inventory full sync",
		"revision", update.Revision,
		"jobs", len(jobs),
		"checks", len(checks),
		"chunks", chunkCount)
}

func applyIncrementalUpdate(
	pools *jobPools,
	scheduler *recurringScheduler,
	update *pb.AgentInventoryUpdate,
	out *resultQueue,
) {
	// Stale increments are ignored once the schedule is reconciled; while a
	// refusal is outstanding the revision stamp is held back (see
	// applyInventoryRevision), so a retry of the refused revision applies.
	rejected, _ := pools.rejectedInventory.Load().(string)
	if rejected == "" && update.Revision > 0 && update.Revision <= pools.appliedRevision.Load() {
		slog.Debug("ignoring stale inventory update", "revision", update.Revision)
		return
	}

	expandInventoryJobs(update.Upserts)
	expandInventoryChecks(update.UpsertChecks)

	// Merge the incremental change into the current assignment payloads so
	// unchanged assignments keep their scheduler phase and fingerprint.
	jobs := scheduler.currentJobPayloads()
	removeJobs := make(map[string]struct{}, len(update.RemoveJobIds))
	for _, id := range update.RemoveJobIds {
		removeJobs[id] = struct{}{}
	}
	jobs = filterJobPayloads(jobs, removeJobs)
	jobs = append(jobs, update.Upserts...)

	checks := scheduler.currentCheckPayloads()
	removeChecks := make(map[string]struct{}, len(update.RemoveCheckIds))
	for _, id := range update.RemoveCheckIds {
		removeChecks[id] = struct{}{}
	}
	checks = filterCheckPayloads(checks, removeChecks)
	checks = append(checks, update.UpsertChecks...)

	scheduler.replaceJobs(jobs, pools, out)
	scheduler.replaceChecks(checks, pools, out)
	applySNMPConcurrencySizing(pools, len(jobs))
	noteInventoryFootprint(len(jobs)+len(checks), proto.Size(update))
	pools.applyInventoryRevision("inventory_update", update.Revision)
	slog.Info("applied inventory update",
		"revision", update.Revision,
		"job_upserts", len(update.Upserts),
		"job_removes", len(update.RemoveJobIds),
		"check_upserts", len(update.UpsertChecks),
		"check_removes", len(update.RemoveCheckIds))
}

// applySNMPConcurrencySizing follows the D1 rule once an authoritative
// inventory has landed: the SNMP pool scales with the recurring job count,
// never below its configured floor, and never resizes before the first
// inventory (a device count of zero is not "no devices", it is "unknown").
func applySNMPConcurrencySizing(pools *jobPools, deviceCount int) {
	if pools == nil || pools.snmp == nil || deviceCount <= 0 {
		return
	}
	pools.snmp.setWorkerLimit(snmpConcurrencyLimit(int(agentRuntimeSettings().SNMPConcurrency), deviceCount))
}

// poolsInventoryAssembler stores the full-sync assembly for the poller's
// pool set. The assembler lives exactly as long as the poller: session stop
// cancels the scheduler and the poller's stop drains the pools and releases
// the assembly, so no partial sync survives a rebuild.
func poolsInventoryAssembler(pools *jobPools) *inventoryAssembler {
	// jobPools has no generic attachment point; keep exactly one assembler
	// per poller in a package map keyed by the pools pointer.
	inventoryAssemblersMu.Lock()
	defer inventoryAssemblersMu.Unlock()
	assembler, ok := inventoryAssemblers[pools]
	if !ok {
		assembler = newInventoryAssembler()
		inventoryAssemblers[pools] = assembler
	}
	return assembler
}

// releaseInventoryAssembler drops the poller's assembly state at stop.
func releaseInventoryAssembler(pools *jobPools) {
	inventoryAssemblersMu.Lock()
	defer inventoryAssemblersMu.Unlock()
	delete(inventoryAssemblers, pools)
}

var (
	inventoryAssemblersMu sync.Mutex
	inventoryAssemblers   = make(map[*jobPools]*inventoryAssembler)
)

func expandInventoryChecks(checks []*pb.Check) {
	// Checks carry no OID columns today; the hook exists so a future Check
	// compact form lands in one normalization path.
}

// currentJobPayloads snapshots the recurring job payloads currently
// scheduled, so an incremental update can merge into them without replacing
// unchanged assignments' phases.
func (s *recurringScheduler) currentJobPayloads() []*pb.AgentJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := make([]*pb.AgentJob, 0, len(s.jobs))
	for _, entry := range s.jobs {
		if job, ok := entry.spec.payload.(*pb.AgentJob); ok && job != nil {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

// currentCheckPayloads snapshots the recurring checks currently scheduled.
func (s *recurringScheduler) currentCheckPayloads() []*pb.Check {
	s.mu.Lock()
	defer s.mu.Unlock()
	checks := make([]*pb.Check, 0, len(s.checks))
	for _, entry := range s.checks {
		if check, ok := entry.spec.payload.(*pb.Check); ok && check != nil {
			checks = append(checks, check)
		}
	}
	return checks
}

func filterJobPayloads(jobs []*pb.AgentJob, remove map[string]struct{}) []*pb.AgentJob {
	if len(remove) == 0 {
		return jobs
	}
	filtered := jobs[:0:0]
	for _, job := range jobs {
		if _, removed := remove[job.GetJobId()]; removed {
			continue
		}
		filtered = append(filtered, job)
	}
	return filtered
}

func filterCheckPayloads(checks []*pb.Check, remove map[string]struct{}) []*pb.Check {
	if len(remove) == 0 {
		return checks
	}
	filtered := checks[:0:0]
	for _, check := range checks {
		if _, removed := remove[check.GetId()]; removed {
			continue
		}
		filtered = append(filtered, check)
	}
	return filtered
}
