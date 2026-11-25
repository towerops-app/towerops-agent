package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// resultDropLogInterval bounds repeated spool saturation logs.
var resultDropLogInterval = time.Minute

// outbound is one pre-encoded result addressed to a Phoenix channel event.
// The payload is built exactly once into a pooled buffer (B7): no protobuf
// re-marshal, no base64 string, and no JSON map at enqueue time. It survives
// reconnects without retaining mutable executor state. reserved marks results
// on the bulk lane.
type outbound struct {
	event string
	// protoPayload is the exact protobuf bytes. It is the source of truth for
	// result_batch envelopes and is wrapped into base64 JSON only for a
	// single legacy/V2-text frame.
	protoPayload []byte
	// payload is a prebuilt legacy JSON frame payload, used by direct
	// session tests and by inbound notices that do not originate from a
	// proto.Message executor result.
	payload  json.RawMessage
	reserved bool
	// attempts counts server-rejected deliveries; handleResultReply retries
	// the first rejection and drops the second.
	attempts int
	// Delivery sequence, assigned in send order. The server acks results by
	// sequence; requeued results are cleared and renumbered in send order
	// (issue 5148).
	sequence uint64
	// Delivery lane. Lower is more urgent; see resultPriority.
	lane uint8
	// encodedBytes is the spool charge: the retained payload length.
	encodedBytes int
	// buf owns payload when it was built in a pooled buffer; release returns
	// it once the server (legacy) or the storage ack (result_batch_v1)
	// frees the result.
	buf *bytes.Buffer
}

// wireSize charges the spool conservatively. A raw protobuf result may be
// sent as raw result_batch now and replayed as base64 JSON after reconnect to
// a legacy server, so charge the larger legacy wire representation.
func (o *outbound) wireSize() int {
	if len(o.protoPayload) > 0 {
		encoded := base64.StdEncoding.EncodedLen(len(o.protoPayload))
		return encoded + len(`{"binary":""}`)
	}
	return len(o.payload)
}

// resultQueue is a bounded process-wide spool. Retained payloads are
// bounded by encoded bytes (default 64 MB, --result-spool-bytes). Depth,
// byte usage and drops ride the heartbeat. Every result keeps a delivery
// sequence and stays in the sent ring until the server's cumulative ack
// arrives.
//
// Failed writes use a dedicated retry lane so they remain ahead of newer
// queued measurements.
type resultQueue struct {
	items    chan outbound
	agentCtx context.Context

	// retryMu guards retries, the lane of failed frames kept ahead of newer
	// spooled work. A slice rather than a channel: the lane must hold a whole
	// result_batch frame (resultBatchMaxEnvelopes), and a bounded channel fed
	// by the session loop itself deadlocks the loop when a frame is larger
	// than the lane (issue 5147). Memory stays bounded because retried
	// results keep the spool charge they already carried.
	retryMu sync.Mutex
	retries []outbound

	byteLimit   int64
	byteUsage   atomic.Int64
	depth       atomic.Uint64
	dropped     atomic.Uint64
	nextSeq     atomic.Uint64
	lastDropLog atomic.Int64

	// trapUsage and trapLimit bound the encoded bytes traps may hold inside
	// the shared spool, so a trap flood cannot evict measurement results
	// (issue 5165). Only byte mode charges traps.
	trapUsage atomic.Int64
	trapLimit int64

	// sent is the pending-ack ring (C4/B8): results the agent sent and the
	// server has not yet acknowledged, ordered by sequence. head/count make
	// cumulative acks an O(1) pop from the front instead of a full-map scan.
	sentMu    sync.Mutex
	sent      []outbound
	sentHead  int
	sentCount int
}

// resultIngressDepth bounds the queue handoff between producers and the
// session loop in byte mode. The byte budget is the authoritative memory
// bound; this only keeps the channel itself small while allowing the small
// results that dominate a healthy fleet to use their full byte budget.
const resultIngressDepth = 65536

// newResultQueueForAgentBytes creates the byte-bounded spool (C2).
func newResultQueueForAgentBytes(agentCtx context.Context, byteLimit int64) *resultQueue {
	if byteLimit <= 0 {
		byteLimit = defaultResultSpoolBytes
	}
	trapLimit := byteLimit / trapSpoolShare
	if trapLimit > trapSpoolMaxBytes {
		trapLimit = trapSpoolMaxBytes
	}
	if trapLimit < 1 {
		trapLimit = 1
	}
	return &resultQueue{
		items:     make(chan outbound, resultIngressDepth),
		agentCtx:  agentCtx,
		byteLimit: byteLimit,
		trapLimit: trapLimit,
	}
}

const (
	// trapSpoolShare is the fraction of the result spool traps may occupy;
	// trapSpoolMaxBytes caps that budget absolutely. A flood may delay other
	// traps, never measurements (issue 5165).
	trapSpoolShare    = 8
	trapSpoolMaxBytes = 8 << 20
)

// enqueue queues one completed result, dropping the newest when the bound is
// exhausted. The result's lane is recorded before handoff; the session loop
// picks lanes in priority order (C3).
func (q *resultQueue) enqueue(result outbound) bool {
	// Delivery sequences are assigned in send order (queueResultFrame),
	// not enqueue order: a priority trap that jumps ahead of queued
	// polls must not receive a later sequence than results the server
	// has not been offered yet. Anything re-entering the spool is a
	// replay from an earlier send position; its old sequence is already
	// below the server's handled-through mark, so it is cleared and
	// renumbered in send order (issue 5148).
	result.sequence = 0
	result.lane = resultPriority(result.event, result.reserved)
	result.encodedBytes = result.wireSize()
	trapCharged := false
	if result.event == "trap" {
		for {
			current := q.trapUsage.Load()
			if current+int64(result.encodedBytes) > q.trapLimit {
				q.reportDrop("", result.event)
				return false
			}
			if q.trapUsage.CompareAndSwap(current, current+int64(result.encodedBytes)) {
				trapCharged = true
				break
			}
		}
	}
	for {
		current := q.byteUsage.Load()
		if current+int64(result.encodedBytes) > q.byteLimit {
			if trapCharged {
				q.trapUsage.Add(-int64(result.encodedBytes))
			}
			q.reportDrop("", result.event)
			return false
		}
		if q.byteUsage.CompareAndSwap(current, current+int64(result.encodedBytes)) {
			break
		}
	}
	q.depth.Add(1)
	select {
	case q.items <- result:
		return true
	default:
		// The ingress channel is small and fixed; treat it as bound
		// exhaustion rather than blocking a worker.
		q.releaseCapacity(result, true)
		q.reportDrop("", result.event)
		return false
	}
}

// enqueueBatch reserves a place for every result of a batch at once, so a
// batch is never half-dropped. The first failure rolls back the reservations
// already taken and drops the whole frame.
func (q *resultQueue) enqueueBatch(results []outbound) bool {
	queued := make([]outbound, 0, len(results))
	for _, result := range results {
		if q.enqueue(result) {
			// enqueue charges wireSize(), not the caller's encodedBytes; keep
			// the charged value so rollback releases the exact same budget.
			result.encodedBytes = result.wireSize()
			queued = append(queued, result)
			continue
		}
		for _, taken := range queued {
			// Remove the just-queued copies; the caller retries the batch
			// once capacity recovers. Buffers stay with the payloads.
			q.releaseCapacity(taken, false)
		}
		return false
	}
	return true
}

// enqueueAfter queues result once delay has passed. The timer goroutine
// holds the payload outside the spool until then; enqueue is safe from any
// goroutine. The spool is process-wide, so the retry still lands when the
// session that scheduled it has ended.
func (q *resultQueue) enqueueAfter(result outbound, delay time.Duration) {
	time.AfterFunc(delay, func() {
		q.enqueue(result)
	})
}

// hold records a sent result in the pending-ack ring. Byte mode only: the
// result's capacity stays charged until ackThrough/dropSent releases it.
func (q *resultQueue) hold(result outbound) {
	if result.sequence == 0 {
		return
	}
	q.sentMu.Lock()
	defer q.sentMu.Unlock()
	if q.sentCount == len(q.sent) {
		grown := make([]outbound, len(q.sent)*2+8)
		for i := range q.sentCount {
			grown[i] = q.sent[(q.sentHead+i)%len(q.sent)]
		}
		q.sent = grown
		q.sentHead = 0
	}
	pos := (q.sentHead + q.sentCount) % len(q.sent)
	q.sent[pos] = result
	q.sentCount++
}

// ackThrough releases every held result up to and including the server's
// cumulative storage sequence. Rejections can re-enter a lower sequence after
// newer ones were sent, so the ring may contain holes: release any entry the
// ack covers and compact the remainder. It returns the highest sequence
// actually released.
func (q *resultQueue) ackThrough(cumulative uint64) uint64 {
	if cumulative == 0 {
		return 0
	}
	q.sentMu.Lock()
	defer q.sentMu.Unlock()
	released := uint64(0)
	kept := make([]outbound, 0, q.sentCount)
	for i := range q.sentCount {
		pos := (q.sentHead + i) % len(q.sent)
		entry := q.sent[pos]
		q.sent[pos] = outbound{}
		if entry.sequence > cumulative {
			kept = append(kept, entry)
			continue
		}
		q.releaseLocked(entry, true)
		if entry.sequence > released {
			released = entry.sequence
		}
	}
	copy(q.sent, kept)
	// Clear the vacated tail so stale payloads never linger in the ring.
	for i := len(kept); i < q.sentCount; i++ {
		q.sent[i] = outbound{}
	}
	q.sentHead = 0
	q.sentCount = len(kept)
	return released
}

// dropSent releases one held result the server explicitly rejected. Used by
// deterministic rejection handling: the result will never be stored, and
// holding its bytes forever would leak the spool budget. Reports whether a
// held entry was found and released, so a caller can skip a second release
// for results that were never in the ring (issue 5151).
func (q *resultQueue) dropSent(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	q.sentMu.Lock()
	defer q.sentMu.Unlock()
	for i := range q.sentCount {
		pos := (q.sentHead + i) % len(q.sent)
		if q.sent[pos].sequence == sequence {
			q.releaseLocked(q.sent[pos], true)
			q.sent[pos] = outbound{}
			// Keep ordering dense: shift the tail one slot forward.
			for j := i + 1; j < q.sentCount; j++ {
				from := (q.sentHead + j) % len(q.sent)
				to := (q.sentHead + j - 1) % len(q.sent)
				q.sent[to] = q.sent[from]
			}
			last := (q.sentHead + q.sentCount - 1) % len(q.sent)
			q.sent[last] = outbound{}
			q.sentCount--
			return true
		}
	}
	return false
}

// releaseLocked frees a held result's capacity. returnBuf hands the pooled
// payload buffer back to the pool; retry paths must pass false because the
// same buffer carries the payload back into the spool.
func (q *resultQueue) releaseLocked(result outbound, returnBuf bool) {
	if result.event == "trap" {
		q.trapUsage.Add(-int64(result.encodedBytes))
	}
	if remaining := q.byteUsage.Add(-int64(result.encodedBytes)); remaining < 0 {
		// A negative balance means a result was released twice, which is a
		// spool accounting bug, not load. The counter is left negative so the
		// heartbeat reports the corruption rather than hiding it (issue 5151).
		slog.Error("result spool byte usage went negative",
			"remaining_bytes", remaining, "sequence", result.sequence)
	}
	q.depth.Add(^uint64(0))
	if returnBuf && result.buf != nil {
		putFrameBuffer(result.buf)
	}
}

// unhold removes one held sequence before its retry re-enters the spool. The
// payload buffer is retained: the retry sends the exact same bytes.
func (q *resultQueue) unhold(sequence uint64) {
	if sequence == 0 {
		return
	}
	q.sentMu.Lock()
	defer q.sentMu.Unlock()
	for i := range q.sentCount {
		pos := (q.sentHead + i) % len(q.sent)
		if q.sent[pos].sequence == sequence {
			q.releaseLocked(q.sent[pos], false)
			q.sent[pos] = outbound{}
			// Keep ordering dense: shift the tail one slot forward.
			for j := i + 1; j < q.sentCount; j++ {
				from := (q.sentHead + j) % len(q.sent)
				to := (q.sentHead + j - 1) % len(q.sent)
				q.sent[to] = q.sent[from]
			}
			last := (q.sentHead + q.sentCount - 1) % len(q.sent)
			q.sent[last] = outbound{}
			q.sentCount--
			return
		}
	}
}

// releaseCapacity frees the retained capacity of a result without the sent
// ring. returnBuf releases the pooled payload buffer only when the payload
// is not about to retry.
func (q *resultQueue) releaseCapacity(result outbound, returnBuf bool) {
	if result.event == "trap" {
		q.trapUsage.Add(-int64(result.encodedBytes))
	}
	if remaining := q.byteUsage.Add(-int64(result.encodedBytes)); remaining < 0 {
		slog.Error("result spool byte usage went negative",
			"remaining_bytes", remaining, "sequence", result.sequence)
	}
	q.depth.Add(^uint64(0))
	if returnBuf && result.buf != nil {
		putFrameBuffer(result.buf)
	}
}

// ack releases a result the writer acknowledged. The charge normally stays
// held for the server's storage ack, but a direct consumer (tests) acks
// without the ring, so the release is exclusive: a result still held in the
// sent ring is freed there, and only a result the ring never saw takes the
// capacity path, or both run and byteUsage dives negative (issue 5151).
func (q *resultQueue) ack(result outbound) {
	if !q.dropSent(result.sequence) {
		q.releaseCapacity(result, true)
	}
}

// retry puts a failed frame's result back at the head of the spool. The lane
// is the session loop's own deque, so it can never block its only consumer.
func (q *resultQueue) retry(result outbound) {
	// The retry goes out after whatever newer work was already framed, so a
	// kept sequence would land below handled-through and the server would
	// refuse the whole frame (issue 5148). It renumbers in send order.
	result.sequence = 0
	q.retryMu.Lock()
	q.retries = append(q.retries, result)
	q.retryMu.Unlock()
}

// retryBatch returns every result of a failed frame to the retry lane ahead
// of newer work. It must never block: a frame can hold
// resultBatchMaxEnvelopes results and the session loop is both the producer
// and the only consumer (issue 5147).
func (q *resultQueue) retryBatch(results []outbound) {
	// Sequences are per-connection and assigned in send order; a retried
	// frame is renumbered like any other requeue (issue 5148).
	for i := range results {
		results[i].sequence = 0
	}
	q.retryMu.Lock()
	q.retries = append(q.retries, results...)
	q.retryMu.Unlock()
}

func (q *resultQueue) takeRetry() (outbound, bool) {
	q.retryMu.Lock()
	defer q.retryMu.Unlock()
	if len(q.retries) == 0 {
		return outbound{}, false
	}
	result := q.retries[0]
	q.retries[0] = outbound{}
	q.retries = q.retries[1:]
	return result, true
}

// requeueUnacked moves held, unacknowledged results back into the spool so a
// reconnect resends them (C4). Sequences are per-connection, so the queue
// clears them on re-entry and the replay renumbers in send order behind
// whatever the outage already queued (issue 5148). The capacity is already
// charged, so byte mode releases the held entry and re-enqueues the same
// payload; a truly saturated spool drops it instead of leaking the ring.
func (q *resultQueue) requeueUnacked() {
	q.sentMu.Lock()
	held := make([]outbound, 0, q.sentCount)
	for i := range q.sentCount {
		pos := (q.sentHead + i) % len(q.sent)
		if q.sent[pos].sequence != 0 {
			held = append(held, q.sent[pos])
		}
		q.sent[pos] = outbound{}
	}
	q.sentHead = 0
	q.sentCount = 0
	q.sentMu.Unlock()
	for _, result := range held {
		q.releaseLocked(result, false)
		q.enqueue(result)
	}
}

// requeueLanes returns results the loop staged but did not send before the
// session ended. The staged charge is released and re-enqueued so a full
// spool applies normal drop accounting.
func (q *resultQueue) requeueLanes(lanes *[5][]outbound) {
	for lane := range lanes {
		for _, result := range lanes[lane] {
			q.releaseCapacity(result, false)
			q.enqueue(result)
		}
		lanes[lane] = nil
	}
}

// empty reports whether nothing is queued, in flight or awaiting an ack.
// Shared by the self-update drain and the shutdown drain.
func (q *resultQueue) empty() bool {
	q.sentMu.Lock()
	pendingAcks := q.sentCount
	q.sentMu.Unlock()
	q.retryMu.Lock()
	retryLen := len(q.retries)
	q.retryMu.Unlock()
	return pendingAcks == 0 && len(q.items) == 0 && retryLen == 0
}

// base64BinaryPayload wraps exact protobuf bytes in the legacy channel object.
// It is only used when an endpoint did not confirm the raw capability lane.
func base64BinaryPayload(raw []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(raw)
	data := make([]byte, 0, len(encoded)+len(`{"binary":""}`))
	data = append(data, `{"binary":"`...)
	data = append(data, encoded...)
	data = append(data, `"}`...)
	return data
}

// encodeOutbound marshals one result and keeps its exact protobuf bytes.
func encodeOutbound(event string, msg proto.Message, jobID string) (outbound, bool) {
	if result, ok := msg.(*pb.SnmpResult); ok && result != nil {
		result.ResultBytes = 0
		base, err := proto.Marshal(result)
		if err != nil {
			slog.Error("marshal protobuf", "job_id", jobID, "event", event, "error", err)
			return outbound{}, false
		}
		// Field 13 includes its own tag and varint in the reported size.
		// Solve the small fixed point, then marshal the final form.
		size := len(base) + 2
		for {
			next := len(base) + 1 + varintLen(size)
			if next == size {
				break
			}
			size = next
		}
		result.ResultBytes = uint32(size)
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		slog.Error("marshal protobuf", "job_id", jobID, "event", event, "error", err)
		return outbound{}, false
	}
	return outbound{
		event:        event,
		protoPayload: raw,
		reserved:     usesReservedLane(msg),
	}, true
}

// usesReservedLane reports whether a result message carries data the server
// cannot re-request — a discovery report or a config backup — and therefore
// qualifies for the reserved spool lane.
func usesReservedLane(msg proto.Message) bool {
	switch m := msg.(type) {
	case *pb.SnmpResult:
		return m.JobType == pb.JobType_DISCOVER
	case *pb.ConfigBackupResult:
		return true
	default:
		return false
	}
}

// sendResult queues a completed measurement for at-most-once WebSocket
// delivery. Cancellation means no measurement was completed and is never
// translated into a failure result.
func sendResult(ctx context.Context, out *resultQueue, event string, msg proto.Message, jobID string) bool {
	if ctx.Err() != nil {
		if out.agentCtx.Err() != nil {
			slog.Debug("result dropped, agent stopped", "job_id", jobID, "event", event)
		} else {
			slog.Debug("result discarded, job cancelled", "job_id", jobID, "event", event)
		}
		return false
	}
	result, ok := encodeOutbound(event, msg, jobID)
	if !ok {
		return false
	}
	if out.enqueue(result) {
		return true
	}
	if out.agentCtx.Err() != nil {
		slog.Debug("result dropped, agent stopped", "job_id", jobID, "event", event)
		return false
	}
	out.reportDrop(jobID, event)
	return false
}

func (q *resultQueue) reportDrop(jobID, event string) {
	dropped := q.dropped.Add(1)
	resultQueueDroppedTotal.Add(1)
	recordJobDropped()
	// Trap spool refusals are counted by the trap path with
	// countTrapSpoolDrop; reportDrop stays generic so the same result is
	// never added twice.
	now := time.Now().UnixNano()
	last := q.lastDropLog.Load()
	if last != 0 && now-last < int64(resultDropLogInterval) {
		return
	}
	if q.lastDropLog.CompareAndSwap(last, now) {
		slog.Error("result buffer full - agent overloaded",
			"job_id", jobID,
			"event", event,
			"dropped", dropped,
		)
	}
}
