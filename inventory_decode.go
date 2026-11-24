// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// inventoryDecodeQueueDepth bounds how many raw inventory frames wait for the
// decoder. Each holds one inbound frame (JSON envelope + base64 string), so
// the session loop stays responsive while multi-megabyte payloads decode.
const inventoryDecodeQueueDepth = 2

// inventoryDecodeRequest is one raw inventory frame waiting for decode.
type inventoryDecodeRequest struct {
	event    string
	payload  json.RawMessage
	rawProto bool
}

// inventoryDecodeResult carries one decoded inventory payload back to the
// session loop, which applies it in arrival order.
type inventoryDecodeResult struct {
	event   string
	jobs    *pb.AgentJobList
	checks  *pb.CheckList
	update  *pb.AgentInventoryUpdate
	decoded bool
}

// startInventoryDecoder launches the per-session decode goroutine. It ends
// with the session context; stop closes the work channel.
func (s *session) startInventoryDecoder() {
	if s.inventoryWork != nil {
		return
	}
	s.inventoryWork = make(chan inventoryDecodeRequest, inventoryDecodeQueueDepth)
	s.inventoryResult = make(chan inventoryDecodeResult, inventoryDecodeQueueDepth)
	go func() {
		for request := range s.inventoryWork {
			result := decodeInventoryRequest(request)
			select {
			case s.inventoryResult <- result:
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// isInventoryEvent reports whether the session loop must route the frame to
// the inventory decoder rather than the generic handler.
func (s *session) isInventoryEvent(event string) bool {
	switch event {
	case "jobs", "check_jobs":
		return true
	case "inventory_update":
		return s.inventoryUpdates
	default:
		return false
	}
}

// decodeInventoryRequest decodes one frame off the session loop. A payload
// that fails the bounded decode is reported as undecoded so the loop applies
// the same rejection path as the synchronous handler.
func decodeInventoryRequest(request inventoryDecodeRequest) inventoryDecodeResult {
	switch request.event {
	case "jobs":
		var list pb.AgentJobList
		if decodeCapabilityPayload(false, request.event, request.payload, &list) {
			return inventoryDecodeResult{event: request.event, jobs: &list, decoded: true}
		}
	case "check_jobs":
		var list pb.CheckList
		if decodeCapabilityPayload(false, request.event, request.payload, &list) {
			return inventoryDecodeResult{event: request.event, checks: &list, decoded: true}
		}
	case "inventory_update":
		var update pb.AgentInventoryUpdate
		if decodeCapabilityPayload(
			request.rawProto,
			request.event,
			request.payload,
			&update,
		) {
			// Normalize compact OID columns while the payload is off the
			// loop; application stays on the loop for scheduler safety.
			expandInventoryJobs(update.Upserts)
			expandInventoryChecks(update.UpsertChecks)
			return inventoryDecodeResult{event: request.event, update: &update, decoded: true}
		}
	}
	return inventoryDecodeResult{event: request.event}
}

// applyInventoryDecode applies a decoded frame from the session loop. The
// application itself is cheap map/scheduler bookkeeping; the expensive
// protobuf decode already ran off the loop.
func (s *session) applyInventoryDecode(result inventoryDecodeResult, pools *jobPools, out *resultQueue) {
	if !result.decoded {
		pools.rejectInventory(result.event)
		reportPayloadRejection(out.agentCtx, out, result.event)
		return
	}
	switch result.event {
	case "jobs":
		applyJobList(s.jobCtx, result.event, result.jobs, pools, out)
	case "check_jobs":
		applyCheckList(s.jobCtx, result.event, result.checks, pools, out)
	case "inventory_update":
		if s.poller != nil {
			s.poller.applyInventoryUpdate(result.update, out)
			return
		}
		applyInventoryUpdate(pools, s.scheduler, result.update, out)
	}
}

// applyJobList applies a decoded "jobs" frame. Shared by the synchronous
// compatibility handler and the async decoder.
func applyJobList(
	ctx context.Context,
	event string,
	jobList *pb.AgentJobList,
	pools *jobPools,
	out *resultQueue,
) {
	if pools.stopAccepting.Load() {
		refuseInventory(ctx, pools, out, event)
		return
	}
	if !pools.localScheduling {
		pools.scheduler.replaceJobs(nil, pools, out)
		for _, job := range jobList.Jobs {
			if job != nil {
				expandJobQueries(job)
				dispatchJob(ctx, job, pools, out)
			}
		}
		return
	}

	recurring, oneShot := splitRecurringJobs(jobList.Jobs)
	slog.Info("received recurring jobs", "count", len(recurring))
	// A jobs frame containing only ad-hoc work is not an authoritative
	// inventory. Preserve scheduled assignments until an interval-bearing
	// or explicitly empty inventory arrives.
	if len(recurring) > 0 || len(jobList.Jobs) == 0 {
		expandInventoryJobs(recurring)
		pools.scheduler.replaceJobs(recurring, pools, out)
		pools.applyInventoryRevision(event, jobList.Revision)
		noteInventoryFootprint(len(recurring), proto.Size(jobList))
	}
	for _, job := range oneShot {
		expandJobQueries(job)
		slog.Info("received one-shot job", "job_id", job.JobId, "type", job.JobType)
		dispatchJob(ctx, job, pools, out)
	}
}

// applyCheckList applies a decoded "check_jobs" frame.
func applyCheckList(
	ctx context.Context,
	event string,
	checkList *pb.CheckList,
	pools *jobPools,
	out *resultQueue,
) {
	if pools.stopAccepting.Load() {
		refuseInventory(ctx, pools, out, event)
		return
	}
	if !pools.localScheduling {
		pools.scheduler.replaceChecks(nil, pools, out)
		for _, check := range checkList.Checks {
			if check != nil {
				_ = submitCheck(ctx, check, pools, out, func() {}, false)
			}
		}
		return
	}
	slog.Info("received recurring checks", "count", len(checkList.Checks))
	pools.scheduler.replaceChecks(checkList.Checks, pools, out)
	pools.applyInventoryRevision(event, checkList.Revision)
	noteInventoryFootprint(len(checkList.Checks), proto.Size(checkList))
}
