// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

func TestSendResultChargesRawWireSize(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	msg := &pb.SnmpResult{JobId: "charge-me", Final: true}
	sendResult(context.Background(), q, "result", msg, msg.JobId)

	item := <-q.items
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	want := base64.StdEncoding.EncodedLen(len(raw)) + len(`{"binary":""}`)
	if item.encodedBytes != want || q.byteUsage.Load() != int64(want) {
		t.Fatalf("raw wire charge = item %d/queue %d, want %d",
			item.encodedBytes, q.byteUsage.Load(), want)
	}
}

func TestResultBatchCarriesRawProtobuf(t *testing.T) {
	source := &pb.SnmpResult{JobId: "raw-envelope", Final: true}
	item, ok := encodeOutbound("result", source, source.JobId)
	if !ok {
		t.Fatal("encodeOutbound failed")
	}
	batch := encodeResultBatch([]outbound{item})
	if len(batch.Results) != 1 {
		t.Fatalf("batch envelopes = %d, want 1", len(batch.Results))
	}
	var decoded pb.SnmpResult
	if err := proto.Unmarshal(batch.Results[0].Payload, &decoded); err != nil {
		t.Fatalf("decode raw envelope: %v", err)
	}
	if decoded.JobId != source.JobId || !decoded.Final {
		t.Fatalf("decoded envelope = %+v", &decoded)
	}
}

func TestPhoenixV2ClientPushGoldenFrame(t *testing.T) {
	payload := []byte(`{"binary":"e30="}`)
	buf, data, err := encodePhoenixV2Push(
		"agent:test", "result_batch", "1", "17", payload)
	if err != nil {
		t.Fatalf("V2 push: %v", err)
	}
	defer putFrameBuffer(buf)

	want := []byte{
		0x00, // client push
		0x01, 0x02, 0x0a, 0x0c,
		'1',
		'1', '7',
		'a', 'g', 'e', 'n', 't', ':', 't', 'e', 's', 't',
		'r', 'e', 's', 'u', 'l', 't', '_', 'b', 'a', 't', 'c', 'h',
	}
	want = append(want, payload...)
	if !bytes.Equal(data, want) {
		t.Fatalf("V2 push = %#x, want %#x", data, want)
	}
}

func TestPhoenixV2TextArrayGoldenFrame(t *testing.T) {
	buf, data, err := encodePhoenixV2Text(
		"agent:test", "phx_join", "1", new("17"), []byte(`{"token":"x"}`))
	if err != nil {
		t.Fatalf("encode V2 text: %v", err)
	}
	defer putFrameBuffer(buf)
	want := []byte(`["1","17","agent:test","phx_join",{"token":"x"}]`)
	if !bytes.Equal(data, want) {
		t.Fatalf("V2 join = %q, want %q", data, want)
	}

	msg, err := decodePhoenixMessage(websocket.MessageText, data)
	if err != nil {
		t.Fatalf("decode V2 text: %v", err)
	}
	if msg.Topic != "agent:test" || msg.Event != "phx_join" ||
		msg.Ref == nil || *msg.Ref != "17" || msg.JoinRef != "1" ||
		!bytes.Equal(msg.Payload, []byte(`{"token":"x"}`)) {
		t.Fatalf("decoded V2 text = %+v", msg)
	}
}

func TestPhoenixV2ServerPushGoldenFrame(t *testing.T) {
	// Server pushes have no ref: kind, join_ref/topic/event lengths, then
	// join_ref, topic, event and payload.
	data := []byte{
		0x00,
		0x01, 0x0a, 0x04,
		'1',
		'a', 'g', 'e', 'n', 't', ':', 't', 'e', 's', 't',
		'j', 'o', 'b', 's',
		'{', '}',
	}
	msg, err := decodePhoenixMessage(websocket.MessageBinary, data)
	if err != nil {
		t.Fatalf("decode server push: %v", err)
	}
	if msg.Topic != "agent:test" || msg.Event != "jobs" || msg.JoinRef != "1" ||
		msg.Ref != nil || !bytes.Equal(msg.Payload, []byte(`{}`)) {
		t.Fatalf("decoded server push = %+v", msg)
	}
}

func TestPhoenixV2BinaryReplyGoldenFrame(t *testing.T) {
	data := []byte{
		0x01,
		0x01, 0x01, 0x07, 0x02,
		'1',
		'1',
		'p', 'h', 'o', 'e', 'n', 'i', 'x',
		'o', 'k',
		'{', '}',
	}
	msg, err := decodePhoenixMessage(websocket.MessageBinary, data)
	if err != nil {
		t.Fatalf("decode binary reply: %v", err)
	}
	if msg.Event != "phx_reply" || msg.Topic != "phoenix" || msg.Status != "ok" ||
		msg.Ref == nil || *msg.Ref != "1" || !bytes.Equal(msg.Payload, []byte(`{}`)) {
		t.Fatalf("decoded binary reply = %+v", msg)
	}
}

func TestDecodeChannelFrameKeepsLegacyJSON(t *testing.T) {
	data, _ := json.Marshal(channelMsg{
		Topic: "agent:test", Event: "phx_reply", Payload: json.RawMessage(`{}`),
	})
	msg, err := decodeChannelFrame(data)
	if err != nil {
		t.Fatalf("decode legacy frame: %v", err)
	}
	if msg.Event != "phx_reply" {
		t.Fatalf("event = %q, want phx_reply", msg.Event)
	}
}

// TestResultQueueByteBoundAndAck verifies the C2/C4 pairing: capacity drops
// the newest result at the byte limit, and the sent ring releases its bytes
// only when the cumulative storage ack covers the sequence.
func TestResultQueueByteBoundAndAck(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1000)
	first := outbound{event: "result", payload: json.RawMessage(make([]byte, 600))}
	if !q.enqueue(first) {
		t.Fatal("enqueue under the byte limit failed")
	}
	second := outbound{event: "result", payload: json.RawMessage(make([]byte, 600))}
	if q.enqueue(second) {
		t.Fatal("enqueue above the byte limit succeeded")
	}
	if got := q.dropped.Load(); got != 1 {
		t.Fatalf("drop count = %d, want 1", got)
	}
	if got := q.depth.Load(); got != 1 {
		t.Fatalf("depth = %d, want 1", got)
	}

	taken := <-q.items
	// Production assigns delivery sequences when a frame is formed; simulate
	// that handoff here so the pending-ack ring sees a real send.
	taken.sequence = 1
	taken.encodedBytes = len(taken.payload)
	q.hold(taken)
	if q.pendingAckCount() != 1 {
		t.Fatal("held result missing from the pending-ack ring")
	}
	if released := q.ackThrough(taken.sequence); released != taken.sequence {
		t.Fatalf("ackThrough released %d, want %d", released, taken.sequence)
	}
	if q.pendingAckCount() != 0 || q.depth.Load() != 0 || q.byteUsage.Load() != 0 {
		t.Fatalf("ack did not release capacity: depth=%d bytes=%d held=%d",
			q.depth.Load(), q.byteUsage.Load(), q.pendingAckCount())
	}
}

// TestNextResultFramePrioritiesAndBatch verifies C3 and D5 ordering: outage
// signals flush immediately, polls and traps hold for the 250 ms window, and
// the held batch stays in stable order. Traps ride their own lowest lane so a
// flood can never starve measurements (issue 5165).
func TestNextResultFramePrioritiesAndBatch(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	s := &session{resultBatches: true, results: q}
	signal := outbound{event: "monitoring_check", payload: json.RawMessage(`{}`)}
	trap := outbound{event: "trap", payload: json.RawMessage(`{}`)}
	poll := outbound{event: "result", payload: json.RawMessage(`{}`)}
	if !q.enqueue(signal) || !q.enqueue(trap) || !q.enqueue(poll) {
		t.Fatal("enqueue failed")
	}

	var lanes [5][]outbound
	s.stageResults(&lanes)
	frame, event := s.nextResultFrame(&lanes, false)
	if len(frame) != 1 || frame[0].event != "monitoring_check" || event != "monitoring_check" {
		t.Fatalf("first frame = %v (%q), want monitoring_check", frame, event)
	}
	frame, _ = s.nextResultFrame(&lanes, false)
	if len(frame) != 0 {
		t.Fatalf("poll or trap flushed before the batch window: %v", frame)
	}
	if len(lanes[2]) != 1 || len(lanes[4]) != 1 {
		t.Fatalf("held lanes = poll %d trap %d, want 1 each", len(lanes[2]), len(lanes[4]))
	}
	frame, event = s.nextResultFrame(&lanes, true)
	if len(frame) != 2 || frame[0].event != "result" || frame[1].event != "trap" || event != "result" {
		t.Fatalf("flush frame = %v (%q), want [result trap]", frame, event)
	}
}

// TestQueuedResultBatchAssignsSequenceBeforeEncoding pins the order inside
// queueResultFrame: the delivery sequence is assigned before the batch is
// encoded. Encoding first put sequence 0 on every fresh batch, and the server
// refuses a batch whose first sequence is not above the position it has already
// handled ("Refusing out-of-order or duplicate result_batch sequences"), so
// those results were dropped and the ack that would have released them never
// arrived.
func TestQueuedResultBatchAssignsSequenceBeforeEncoding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var encoded []uint64
	orig := resultBatchEncoder
	resultBatchEncoder = func(results []outbound) *pb.AgentResultBatch {
		for _, result := range results {
			encoded = append(encoded, result.sequence)
		}
		return orig(results)
	}
	t.Cleanup(func() { resultBatchEncoder = orig })

	s := &session{
		ctx: ctx, v2: true, resultBatches: true, topic: "agent:test",
		results:            newResultQueueForAgentBytes(ctx, 1<<20),
		writeCh:            make(chan writeRequest, 4),
		serverCapabilities: map[string]struct{}{"result_batch_v1": {}},
	}

	w, err := s.queueResultFrame([]outbound{{event: "result", protoPayload: []byte("x")}}, "result", true)
	if err != nil {
		t.Fatalf("queueResultFrame: %v", err)
	}

	if len(encoded) != 1 {
		t.Fatalf("encoder saw %d results, want 1", len(encoded))
	}
	if encoded[0] == 0 {
		t.Fatal("envelope encoded with sequence 0: the batch is built before the delivery sequence is assigned")
	}
	if encoded[0] != w.results[0].sequence {
		t.Fatalf("encoded sequence = %d, held sequence = %d", encoded[0], w.results[0].sequence)
	}
}

func TestResultBatchEncodingCarriesSequences(t *testing.T) {
	results := []outbound{
		{event: "check_result", payload: json.RawMessage(`{}`), sequence: 4},
		{event: "result", payload: json.RawMessage(`{}`), sequence: 5},
	}
	batch := encodeResultBatch(results)
	if len(batch.Results) != 2 {
		t.Fatalf("batch length = %d, want 2", len(batch.Results))
	}
	for i, envelope := range batch.Results {
		if envelope.Event != results[i].event || envelope.Sequence != results[i].sequence {
			t.Fatalf("envelope %d = %q/%d", i, envelope.Event, envelope.Sequence)
		}
	}
}

// TestResultQueueNegativeByteUsageLogs covers the corruption canary: the
// exclusive release in ack removes the known double-release, and any future
// path that frees a result twice must still surface as an error log rather
// than silently corrupting the spool budget (issue 5151).
func TestResultQueueNegativeByteUsageLogs(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	q.releaseLocked(outbound{sequence: 1, encodedBytes: 5}, false)
	q.releaseCapacity(outbound{sequence: 2, encodedBytes: 5}, false)
	if got := q.byteUsage.Load(); got != -10 {
		t.Fatalf("byteUsage = %d, want -10", got)
	}
}

// TestRequeueUnackedRenumbersReplay verifies reconnect replay of a held
// result whose storage ack never arrived. Sequences are per-connection, so
// the replay must re-enter unnumbered and pick up a fresh sequence in send
// order rather than landing below the new session's handled-through mark
// (issue 5148).
func TestRequeueUnackedRenumbersReplay(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	result := outbound{event: "result", payload: json.RawMessage(`{}`)}
	if !q.enqueue(result) {
		t.Fatal("enqueue failed")
	}
	taken := <-q.items
	taken.sequence = 3
	taken.encodedBytes = len(taken.payload)
	q.hold(taken)

	q.requeueUnacked()
	select {
	case replayed := <-q.items:
		if replayed.sequence != 0 {
			t.Fatalf("replayed sequence = %d, want 0 so the next frame renumbers it", replayed.sequence)
		}
		q.ack(replayed)
	default:
		t.Fatal("held result was not replayed after disconnect")
	}
	if q.pendingAckCount() != 0 || q.depth.Load() != 0 {
		t.Fatalf("replay leaked capacity: held=%d depth=%d",
			q.pendingAckCount(), q.depth.Load())
	}
}

// sequenceRecorder swaps the result_batch encoder seam for one that records
// the delivery sequence of every envelope it frames.
func sequenceRecorder(t *testing.T) *[][]uint64 {
	t.Helper()
	var frames [][]uint64
	orig := resultBatchEncoder
	resultBatchEncoder = func(results []outbound) *pb.AgentResultBatch {
		var sequences []uint64
		for _, result := range results {
			sequences = append(sequences, result.sequence)
		}
		frames = append(frames, sequences)
		return orig(results)
	}
	t.Cleanup(func() { resultBatchEncoder = orig })
	return &frames
}

// batchSession builds a byte-bounded session with result_batch_v1 negotiated,
// the shape the production loop sends frames through.
func batchSession(ctx context.Context) *session {
	return &session{
		ctx: ctx, v2: true, resultBatches: true, topic: "agent:test",
		results:            newResultQueueForAgentBytes(ctx, 1<<20),
		writeCh:            make(chan writeRequest, 8),
		serverCapabilities: map[string]struct{}{"result_batch_v1": {}},
	}
}

// sendFrame stages every spooled result into one frame the way the session
// loop does and queues it for the writer.
func sendFrame(t *testing.T, s *session) {
	t.Helper()
	var lanes [5][]outbound
	s.stageResults(&lanes)
	frame, event := s.nextResultFrame(&lanes, true)
	if len(frame) == 0 {
		t.Fatal("no frame staged")
	}
	if _, err := s.queueResultFrame(frame, event, true); err != nil {
		t.Fatalf("queueResultFrame: %v", err)
	}
}

func strictlyIncreasing(sequences []uint64) bool {
	for i := 1; i < len(sequences); i++ {
		if sequences[i] <= sequences[i-1] {
			return false
		}
	}
	return true
}

// Issue 5148: results held for a storage ack replay after a reconnect with
// fresh sequences in send order. Keeping their old numbers put them below
// the fresh results produced during the outage, and the server refused the
// whole frame; the next cumulative ack then freed results it never stored.
func TestReconnectReplayFramesStrictlyIncreasing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := sequenceRecorder(t)
	s := batchSession(ctx)

	s.results.enqueue(outbound{event: "result", protoPayload: []byte("a")})
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("b")})
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("c")})
	sendFrame(t, s) // sequences 1-3, held awaiting the storage ack

	// Fresh results produced while the session was down sit ahead of the
	// replay in the spool.
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("d")})
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("e")})
	s.results.requeueUnacked()
	sendFrame(t, s)

	if len(*frames) != 2 {
		t.Fatalf("frames = %v, want 2", *frames)
	}
	replay := (*frames)[1]
	if len(replay) != 5 {
		t.Fatalf("replay frame = %v, want 5 envelopes", replay)
	}
	if !strictlyIncreasing(replay) || replay[0] <= 3 {
		t.Fatalf("replay sequences %v are not strictly increasing above the first frame", replay)
	}
}

// Issue 5148: a batch the server rejects re-enters the spool after newer
// frames were already numbered. It must renumber in send order too, or the
// retry lands below handled-through and is refused with its fresh neighbors.
func TestRejectedBatchRenumbersAboveLaterFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := sequenceRecorder(t)
	s := batchSession(ctx)

	s.results.enqueue(outbound{event: "result", protoPayload: []byte("a")})
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("b")})
	sendFrame(t, s) // sequences 1-2
	rejected := (*frames)[0]

	s.results.enqueue(outbound{event: "result", protoPayload: []byte("c")})
	s.results.enqueue(outbound{event: "result", protoPayload: []byte("d")})
	sendFrame(t, s) // sequences 3-4

	// The rejection of the first frame arrives after the second was sent.
	s.requeueRejected([]outbound{
		{event: "result", protoPayload: []byte("a"), sequence: rejected[0], encodedBytes: 1},
		{event: "result", protoPayload: []byte("b"), sequence: rejected[1], encodedBytes: 1},
	}, 0)
	sendFrame(t, s)

	retry := (*frames)[2]
	if len(retry) != 2 {
		t.Fatalf("retry frame = %v, want 2 envelopes", retry)
	}
	if !strictlyIncreasing(retry) || retry[0] <= 4 {
		t.Fatalf("retry sequences %v are not above the frames already sent", retry)
	}
}

// TestDecodeResultAckForms covers both wire forms: raw protobuf behind a
// binary frame on the V2 capability lane and the legacy binary-envelope JSON
// object on a text frame. The lane follows the frame kind, so a v2 session
// (framing is always V2) still decodes a text-frame base64 ack.
func TestDecodeResultAckForms(t *testing.T) {
	raw, err := proto.Marshal(&pb.AgentResultAck{CumulativeSequence: 9})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := decodeResultAck(channelMsg{Payload: json.RawMessage(raw), Binary: true})
	if !ok || got != 9 {
		t.Fatalf("raw ack = %d/%v, want 9/true", got, ok)
	}

	legacy, err := proto.Marshal(&pb.AgentResultAck{CumulativeSequence: 4})
	if err != nil {
		t.Fatal(err)
	}
	// A capability-less V2 server sends the base64 envelope on a TEXT frame
	// even though the session frames everything as V2. Binary=false must
	// select the legacy decode or every held result leaks until reconnect.
	got, ok = decodeResultAck(channelMsg{Payload: json.RawMessage(
		`{"binary":"` + base64.StdEncoding.EncodeToString(legacy) + `"}`)})
	if !ok || got != 4 {
		t.Fatalf("text-frame ack = %d/%v, want 4/true", got, ok)
	}
}

// TestNextResultFrameLegacySendsHeldLanesImmediately covers the legacy lane:
// a server that never negotiated result_batch_v1 has no flush ticker, so any
// result held for the 250 ms window is stranded. Small DISCOVER identify
// results are held most often, which is what froze `last_discovery_at` for
// every device and stopped polling fleet-wide.
func TestNextResultFrameLegacySendsHeldLanesImmediately(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	s := &session{resultBatches: false, results: q}
	check := outbound{event: "check_result", payload: json.RawMessage(`{}`)}
	identify := outbound{event: "result", payload: json.RawMessage(`{}`), reserved: true}
	if !q.enqueue(check) || !q.enqueue(identify) {
		t.Fatal("enqueue failed")
	}

	var lanes [5][]outbound
	s.stageResults(&lanes)
	if len(lanes[1]) != 1 || len(lanes[3]) != 1 {
		t.Fatalf("staged lanes = %v, want one check_result and one identify result", lanes)
	}

	frame, event := s.nextResultFrame(&lanes, false)
	if len(frame) != 1 || event != "check_result" {
		t.Fatalf("first legacy frame = %v (%q), want check_result", frame, event)
	}
	frame, event = s.nextResultFrame(&lanes, false)
	if len(frame) != 1 || event != "result" {
		t.Fatalf("identify frame = %v (%q), want result", frame, event)
	}
	if frame[0].reserved != true {
		t.Fatalf("identify frame lost its reserved lane marker: %+v", frame[0])
	}
	if len(lanes[1]) != 0 || len(lanes[3]) != 0 {
		t.Fatalf("legacy lanes still hold results: %v", lanes)
	}
}

// TestTrapSpoolBudgetPreservesResults checks the trap sub-budget inside the
// spool: once it is exhausted traps drop but measurement results still fit
// (issue 5165).
func TestTrapSpoolBudgetPreservesResults(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 8192)
	trap := outbound{event: "trap", payload: json.RawMessage(`{}`)}
	for i := 0; i < 2000; i++ {
		if !q.enqueue(trap) {
			break
		}
	}
	if got := q.trapUsage.Load(); got > 8192/trapSpoolShare {
		t.Fatalf("trap usage %d exceeded sub-budget %d", got, 8192/trapSpoolShare)
	}
	if got := q.trapUsage.Load(); got == 0 {
		t.Fatal("trap budget was never charged")
	}
	if !q.enqueue(outbound{event: "result", payload: json.RawMessage(`{}`)}) {
		t.Fatal("trap budget exhaustion refused a measurement result")
	}
}

// TestTrapFloodDoesNotStarveResults stages thousands of traps behind one poll
// result and requires the poll to lead the first frame (issue 5165).
func TestTrapFloodDoesNotStarveResults(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	for i := 0; i < 5000; i++ {
		if !q.enqueue(outbound{event: "trap", payload: json.RawMessage(`{}`)}) {
			t.Fatalf("trap %d refused by spool", i)
		}
	}
	if !q.enqueue(outbound{event: "result", payload: json.RawMessage(`{}`)}) {
		t.Fatal("poll refused")
	}
	s := &session{resultBatches: true, results: q}
	var lanes [5][]outbound
	s.stageResults(&lanes)
	frame, _ := s.nextResultFrame(&lanes, true)
	if len(frame) == 0 || frame[0].event != "result" {
		t.Fatalf("first frame head = %v, want the poll result ahead of the flood", frame)
	}
}

// TestTrapSpoolBudgetReleasesOnSpoolFull: a trap that fits its sub-budget but
// loses the shared byte check must hand the trap charge back (issue 5165).
func TestTrapSpoolBudgetReleasesOnSpoolFull(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 8192)
	if !q.enqueue(outbound{event: "result", payload: make(json.RawMessage, 8191)}) {
		t.Fatal("fill result refused")
	}
	if q.enqueue(outbound{event: "trap", payload: json.RawMessage(`{}`)}) {
		t.Fatal("trap must be refused by the shared byte budget")
	}
	if got := q.trapUsage.Load(); got != 0 {
		t.Fatalf("trap charge leaked into sub-budget: %d", got)
	}
}

func TestHasTrapRoomFor(t *testing.T) {
	count := newResultQueueForAgent(context.Background(), 4)
	if !count.hasTrapRoomFor(1) {
		t.Error("empty count-mode spool must report trap room")
	}
	for i := 0; i < cap(count.items); i++ {
		count.items <- outbound{}
	}
	if count.hasTrapRoomFor(1) {
		t.Error("full count-mode spool must report no trap room")
	}

	q := newResultQueueForAgentBytes(context.Background(), 8192)
	if !q.hasTrapRoomFor(1) {
		t.Error("empty byte spool must report trap room")
	}
	q.trapUsage.Store(q.trapLimit)
	if q.hasTrapRoomFor(1) {
		t.Error("exhausted trap budget must report no room")
	}
	full := newResultQueueForAgentBytes(context.Background(), 1<<30)
	for i := 0; i < cap(full.items); i++ {
		full.items <- outbound{}
	}
	if full.hasTrapRoomFor(1) {
		t.Error("full ingress must report no trap room")
	}
}

func TestResultQueueTinySpoolKeepsTrapBudget(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 4)
	if q.trapLimit != 1 {
		t.Fatalf("trapLimit = %d, want floor of 1", q.trapLimit)
	}
}

func TestTrapReleaseCapacityUncharges(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 8192)
	if !q.enqueue(outbound{event: "trap", payload: json.RawMessage(`{}`)}) {
		t.Fatal("trap enqueue refused")
	}
	got := <-q.items
	q.releaseCapacity(got, true)
	if q.trapUsage.Load() != 0 {
		t.Fatalf("trapUsage = %d after release, want 0", q.trapUsage.Load())
	}
}
