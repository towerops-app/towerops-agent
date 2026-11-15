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
	buf, data, binaryFrame := marshalChannelFrameV2(
		"agent:test", "result_batch", "1", payload, new("17"), true)
	defer putFrameBuffer(buf)
	if !binaryFrame {
		t.Fatal("V2 negotiation produced a JSON frame")
	}

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

// TestNextResultFramePrioritiesAndBatch verifies C3 and D5 ordering: trap and
// ping signals flush immediately, polls hold for the 250 ms window, and the
// held batch stays in stable order.
func TestNextResultFramePrioritiesAndBatch(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	s := &session{resultBatches: true, results: q}
	trap := outbound{event: "trap", payload: json.RawMessage(`{}`)}
	poll := outbound{event: "result", payload: json.RawMessage(`{}`)}
	if !q.enqueue(trap) || !q.enqueue(poll) {
		t.Fatal("enqueue failed")
	}

	var lanes [4][]outbound
	s.stageResults(&lanes)
	frame, event := s.nextResultFrame(&lanes, false)
	if len(frame) != 1 || frame[0].event != "trap" || event != "trap" {
		t.Fatalf("first frame = %v (%q), want trap", frame, event)
	}
	frame, _ = s.nextResultFrame(&lanes, false)
	if len(frame) != 0 {
		t.Fatalf("poll flushed before the batch window: %v", frame)
	}
	if len(lanes[2]) != 1 {
		t.Fatalf("held poll lane length = %d, want 1", len(lanes[2]))
	}
	frame, event = s.nextResultFrame(&lanes, true)
	if len(frame) != 1 || event != "result" {
		t.Fatalf("flush frame = %v (%q), want poll", frame, event)
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

// TestRequeueUnackedPreservesSequences verifies reconnect replay of a held
// result whose storage ack never arrived.
func TestRequeueUnackedPreservesSequences(t *testing.T) {
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
		if replayed.sequence != 3 {
			t.Fatalf("replayed sequence = %d, want 3", replayed.sequence)
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
