// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// Phoenix serializer V2 wire format (see Phoenix Channels "Serializer v2"):
//
//	push:    <join_ref_len> <ref_len> <topic_len> <event_len>
//	         <join_ref> <ref> <topic> <event> <payload>
//	reply:   <join_ref_len> <ref_len> <topic_len> <status_len>
//	         <join_ref> <ref> <topic> <status> <payload>
//
// Every length is one unsigned byte, so protocol identifiers — topic, event,
// ref, status — must fit in 255 bytes. The application payload is arbitrary
// bytes and carries no length prefix: it extends to the end of the frame.
//
// The agent keeps the `%{binary: base64}` JSON payload shape inside V2 frames
// for every application payload, so a V2 transport never changes what the
// channel receives, only how the envelope travels.

const (
	phoenixV2PushKind      byte = 0
	phoenixV2ReplyKind     byte = 1
	phoenixV2BroadcastKind byte = 2
	phoenixV2MaxField           = 255
)

var (
	errPhoenixV2Frame       = errors.New("malformed phoenix v2 frame")
	errPhoenixV2UnknownKind = errors.New("unknown phoenix v2 frame kind")
)

// looksLikePhoenixTextFrame distinguishes the two legal text representations:
// V2 JSON arrays and legacy V1 objects. Binary frames are always dispatched by
// websocket.MessageType, never by content sniffing.
func looksLikePhoenixTextFrame(data []byte) bool {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '['
	}
	return false
}

// decodePhoenixV2Push parses a kind-zero binary client/server push. The server
// push has no ref field.
func decodePhoenixV2Push(data []byte) (channelMsg, error) {
	if len(data) < 4 {
		return channelMsg{}, errPhoenixV2Frame
	}
	joinLen, topicLen, eventLen := int(data[0]), int(data[1]), int(data[2])
	if len(data) < 3+joinLen+topicLen+eventLen {
		return channelMsg{}, errPhoenixV2Frame
	}
	offset := 3
	joinRef := string(data[offset : offset+joinLen])
	offset += joinLen
	topic := string(data[offset : offset+topicLen])
	offset += topicLen
	event := string(data[offset : offset+eventLen])
	offset += eventLen
	return channelMsg{
		JoinRef: joinRef,
		Topic:   topic,
		Event:   event,
		Payload: append(json.RawMessage(nil), data[offset:]...),
	}, nil
}

// appendPhoenixV2Push writes the client push form: kind byte, four field
// lengths, then join_ref, ref, topic, event and payload. Phoenix's server-push
// form has no ref and uses the separate decoder below.
func appendPhoenixV2Push(
	buf *bytes.Buffer,
	topic, event, joinRef, ref string,
	payload []byte,
) error {
	fields := []string{joinRef, ref, topic, event}
	for _, field := range fields {
		if len(field) > phoenixV2MaxField {
			return fmt.Errorf("phoenix v2 field exceeds 255 bytes: %d", len(field))
		}
	}
	buf.WriteByte(phoenixV2PushKind)
	buf.WriteByte(byte(len(joinRef)))
	buf.WriteByte(byte(len(ref)))
	buf.WriteByte(byte(len(topic)))
	buf.WriteByte(byte(len(event)))
	buf.WriteString(joinRef)
	buf.WriteString(ref)
	buf.WriteString(topic)
	buf.WriteString(event)
	buf.Write(payload)
	return nil
}

// encodePhoenixV2Text builds the stock V2 JSON-array text frame.
func encodePhoenixV2Text(topic, event, joinRef string, ref *string, payload []byte) (*bytes.Buffer, []byte, error) {
	refValue := any(nil)
	if ref != nil {
		refValue = *ref
	}
	frame := []any{joinRef, refValue, topic, event, json.RawMessage(payload)}
	buf := framePool.Get().(*bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(frame); err != nil {
		putFrameBuffer(buf)
		return nil, nil, err
	}
	// JSON Encoder appends a newline; Phoenix does not require it, but keeping
	// frames byte-for-byte predictable makes golden tests and logs cleaner.
	data := buf.Bytes()
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	buf.Truncate(len(data))
	return buf, data, nil
}

// decodePhoenixMessage decodes one complete websocket message according to its
// websocket type. Text supports both V2 arrays and the legacy V1 object while
// the agent negotiates an endpoint; binary frames follow Phoenix serializer V2.
func decodePhoenixMessage(kind websocket.MessageType, data []byte) (channelMsg, error) {
	switch kind {
	case websocket.MessageText:
		if looksLikePhoenixTextFrame(data) {
			var fields []json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				return channelMsg{}, fmt.Errorf("phoenix v2 array: %w", err)
			}
			if len(fields) != 5 {
				return channelMsg{}, fmt.Errorf("phoenix v2 array has %d fields, want 5", len(fields))
			}
			msg := channelMsg{}
			if err := json.Unmarshal(fields[0], &msg.JoinRef); err != nil {
				return channelMsg{}, fmt.Errorf("phoenix v2 join ref: %w", err)
			}
			if string(fields[1]) != "null" {
				var ref string
				if err := json.Unmarshal(fields[1], &ref); err != nil {
					return channelMsg{}, fmt.Errorf("phoenix v2 ref: %w", err)
				}
				msg.Ref = &ref
			}
			if err := json.Unmarshal(fields[2], &msg.Topic); err != nil {
				return channelMsg{}, fmt.Errorf("phoenix v2 topic: %w", err)
			}
			if err := json.Unmarshal(fields[3], &msg.Event); err != nil {
				return channelMsg{}, fmt.Errorf("phoenix v2 event: %w", err)
			}
			msg.Payload = append(json.RawMessage(nil), fields[4]...)
			return msg, nil
		}
		return decodeChannelFrame(data)
	case websocket.MessageBinary:
		if len(data) == 0 {
			return channelMsg{}, errPhoenixV2Frame
		}
		switch data[0] {
		case phoenixV2PushKind:
			return decodePhoenixV2Push(data[1:])
		case phoenixV2ReplyKind:
			return decodePhoenixV2Reply(data[1:])
		case phoenixV2BroadcastKind:
			return decodePhoenixV2Broadcast(data[1:])
		default:
			return channelMsg{}, errPhoenixV2UnknownKind
		}
	default:
		return channelMsg{}, fmt.Errorf("%w: %d", errPhoenixV2UnknownKind, kind)
	}
}

// decodePhoenixV2Reply parses Phoenix's binary reply form, exposing its status
// through the same phx_reply event used by the legacy JSON envelope.
func decodePhoenixV2Reply(data []byte) (channelMsg, error) {
	if len(data) < 5 {
		return channelMsg{}, errPhoenixV2Frame
	}
	joinLen, refLen, topicLen, statusLen := int(data[0]), int(data[1]), int(data[2]), int(data[3])
	if len(data) < 4+joinLen+refLen+topicLen+statusLen {
		return channelMsg{}, errPhoenixV2Frame
	}
	offset := 4
	joinRef := string(data[offset : offset+joinLen])
	offset += joinLen
	ref := string(data[offset : offset+refLen])
	offset += refLen
	topic := string(data[offset : offset+topicLen])
	offset += topicLen
	status := string(data[offset : offset+statusLen])
	offset += statusLen
	return channelMsg{
		JoinRef: joinRef,
		Ref:     &ref,
		Topic:   topic,
		Event:   "phx_reply",
		Status:  status,
		Payload: append(json.RawMessage(nil), data[offset:]...),
	}, nil
}

// decodePhoenixV2Broadcast parses Phoenix's binary broadcast form.
func decodePhoenixV2Broadcast(data []byte) (channelMsg, error) {
	if len(data) < 3 {
		return channelMsg{}, errPhoenixV2Frame
	}
	topicLen, eventLen := int(data[0]), int(data[1])
	if len(data) < 2+topicLen+eventLen {
		return channelMsg{}, errPhoenixV2Frame
	}
	offset := 2
	topic := string(data[offset : offset+topicLen])
	offset += topicLen
	event := string(data[offset : offset+eventLen])
	offset += eventLen
	return channelMsg{
		Topic:   topic,
		Event:   event,
		Payload: append(json.RawMessage(nil), data[offset:]...),
	}, nil
}

// encodePhoenixV2Push builds one V2 kind-zero binary push in a pooled buffer.
// The caller releases the buffer with putFrameBuffer once the write completes.
func encodePhoenixV2Push(topic, event, joinRef, ref string, payload []byte) (*bytes.Buffer, []byte, error) {
	buf := framePool.Get().(*bytes.Buffer)
	if err := appendPhoenixV2Push(buf, topic, event, joinRef, ref, payload); err != nil {
		putFrameBuffer(buf)
		return nil, nil, err
	}
	return buf, buf.Bytes(), nil
}

// decodeChannelFrame decodes only the legacy V1 JSON envelope. Production
// inbound dispatch uses decodePhoenixMessage so websocket message kind, not
// content sniffing, selects the Phoenix V2 decoder.
func decodeChannelFrame(data []byte) (channelMsg, error) {
	var msg channelMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return channelMsg{}, err
	}
	return msg, nil
}

// resultBatchFlushDelay coalesces small results for one frame (issue C3/D5).
const resultBatchFlushDelay = 250 * time.Millisecond

// resultBatchFlushBytes flushes a forming batch once its encoded envelopes
// approach the frame target, so latency never waits out a large batch.
const resultBatchFlushBytes = 256 << 10

// batchableEvent reports whether a result is small enough to hold for the
// batch window. Large discovery and backup frames go out alone immediately:
// holding 8 MiB behind a 250 ms timer only delays their own write.
func batchableEvent(event string, size int) bool {
	if size > resultBatchFlushBytes/2 {
		return false
	}
	switch event {
	case "trap", "monitoring_check", "check_result", "result", "mikrotik_result",
		"credential_test_result", "throughput_test_result":
		return true
	default:
		return false
	}
}

// resultPriority ranks the delivery lanes (issue C3): outage signals first,
// then checks, then measurement polls, then one-shot bulk data.
func resultPriority(event string, reserved bool) uint8 {
	if reserved {
		return 3
	}
	switch event {
	case "trap", "monitoring_check":
		return 0
	case "check_result":
		return 1
	default:
		return 2
	}
}

// encodeResultBatch builds the batch envelope. Payload bytes are the exact
// protobuf message bytes; the server routes by envelope.event. The outbound
// result was marshalled once when it entered the spool.
func encodeResultBatch(results []outbound) *pb.AgentResultBatch {
	batch := &pb.AgentResultBatch{
		Results: make([]*pb.AgentResultEnvelope, 0, len(results)),
	}
	for _, result := range results {
		batch.Results = append(batch.Results, &pb.AgentResultEnvelope{
			Event:    result.event,
			Payload:  result.protoPayload,
			Sequence: result.sequence,
		})
	}
	return batch
}

// decodeResultAck unwraps the cumulative storage ack carried by the
// "result_ack" event. A negotiated result_ack_v1 lane carries raw protobuf
// bytes; a legacy server would use the binary-envelope JSON object.
func decodeResultAck(msg channelMsg) (uint64, bool) {
	var ack pb.AgentResultAck
	// The lane follows the inbound frame kind, not session.v2: v2 marks the
	// always-on V2 *framing*, while a server that has not confirmed
	// result_ack_v1 (or runs a V1 serializer) still delivers the ack as a
	// text frame whose payload is %{binary: base64}.
	if !decodeCapabilityPayload(msg.Binary, "result_ack", msg.Payload, &ack) {
		return 0, false
	}
	return ack.CumulativeSequence, true
}

// decodeCapabilityPayload decodes a capability-lane payload. rawProto marks
// the negotiated V2 raw-bytes lane; without it the payload keeps the legacy
// `%{binary: base64}` JSON object.
func decodeCapabilityPayload(
	rawProto bool,
	event string,
	raw json.RawMessage,
	msg proto.Message,
) bool {
	if !rawProto {
		return decodeBinaryPayload(event, raw, msg)
	}
	// The raw lane is bounded by the same decoded-frame memory budget, not
	// its base64 expansion.
	if len(raw) > maxDecodedJobPayloadBytes {
		slog.Error("capability payload too large", "event", event,
			"size", len(raw), "max", maxDecodedJobPayloadBytes)
		return false
	}
	if err := proto.Unmarshal([]byte(raw), msg); err != nil {
		slog.Error("decode capability payload", "event", event, "error", err)
		return false
	}
	return true
}

// stageResults moves everything already available from the retry lane and
// the spool ingress into the delivery lanes. It never blocks.
func (s *session) stageResults(lanes *[4][]outbound) {
	for {
		result, ok := s.results.takeRetry()
		if !ok {
			break
		}
		lanes[result.lane] = append(lanes[result.lane], result)
	}
	for {
		select {
		case result := <-s.results.items:
			lanes[result.lane] = append(lanes[result.lane], result)
		default:
			return
		}
	}
}

// nextResultFrame picks the next frame from the lanes. Lower lane number is
// more urgent. Without result_batch_v1 it is always the single highest-
// priority result; with it, small results accumulate into one frame until
// the byte target, a priority trap/ping arrives, or the flush timer fires.
// Non-batchable bulk results (large discovery/backup frames) go out alone.
func (s *session) nextResultFrame(lanes *[4][]outbound, flushDue bool) ([]outbound, string) {
	// Outage signals preempt a forming lower-priority batch. Send each signal
	// immediately; lower-lane results remain held until the normal batch rule
	// applies.
	if len(lanes[0]) > 0 {
		candidate := lanes[0][0]
		lanes[0] = lanes[0][1:]
		return []outbound{candidate}, candidate.event
	}

	var batch []outbound
	var batchBytes int
	for lane := range lanes {
		for len(lanes[lane]) > 0 {
			candidate := lanes[lane][0]
			if !batchableEvent(candidate.event, candidate.wireSize()) {
				if len(batch) == 0 {
					lanes[lane] = lanes[lane][1:]
					return []outbound{candidate}, candidate.event
				}
				// Flush the higher-priority batch first; the bulk result
				// stays at the head of its lane for the next frame.
				return batch, batch[0].event
			}
			size := candidate.wireSize()
			if len(batch) > 0 && batchBytes+size > resultBatchFlushBytes {
				break
			}
			lanes[lane] = lanes[lane][1:]
			batch = append(batch, candidate)
			batchBytes += size
			if batchBytes >= resultBatchFlushBytes {
				return batch, batch[0].event
			}
		}
	}
	if len(batch) == 0 {
		return nil, ""
	}
	// Other small results wait for the 250 ms flush window; a batch already
	// reached the byte target above, so only held results return here.
	if flushDue {
		return batch, batch[0].event
	}
	// Put the held batch back in front so retry/frame selection stays stable.
	s.unstageBatch(lanes, batch)
	return nil, ""
}

// unstageBatch returns a held batch to the front of its lanes, preserving
// priority order within each lane.
func (s *session) unstageBatch(lanes *[4][]outbound, batch []outbound) {
	byLane := [4][]outbound{}
	for _, result := range batch {
		byLane[result.lane] = append(byLane[result.lane], result)
	}
	for lane, pending := range byLane {
		if len(pending) == 0 {
			continue
		}
		rest := lanes[lane]
		lanes[lane] = append(pending, rest...)
	}
}

// hasRoomFor reports whether the spool can take at least minBytes more
// without dropping a producer's result. Used for trap backpressure (C5).
func (q *resultQueue) hasRoomFor(minBytes int64) bool {
	if !q.byteBounded() {
		return len(q.items) < cap(q.items)
	}
	if len(q.items) >= cap(q.items) {
		return false
	}
	return q.byteUsage.Load()+minBytes <= q.byteLimit
}

// pendingAckCount reports results sent but not yet acknowledged. The
// shutdown drain counts them as deliverable, not lost.
func (q *resultQueue) pendingAckCount() int {
	q.sentMu.Lock()
	defer q.sentMu.Unlock()
	return q.sentCount
}
