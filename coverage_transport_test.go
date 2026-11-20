// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

func TestLooksLikePhoenixTextFrame(t *testing.T) {
	cases := []struct {
		data []byte
		want bool
	}{
		{[]byte(""), false},
		{[]byte("   \t\n  "), false},
		{[]byte(`["1",null,"t","e",{}]`), true},
		{[]byte(`  ["1"]  `), true},
		{[]byte(`{"event":"x"}`), false},
	}
	for _, c := range cases {
		if got := looksLikePhoenixTextFrame(c.data); got != c.want {
			t.Errorf("looksLikePhoenixTextFrame(%q) = %v, want %v", c.data, got, c.want)
		}
	}
}

func TestDecodePhoenixV2Push(t *testing.T) {
	// len(data) < 4
	if _, err := decodePhoenixV2Push([]byte{1, 2}); err == nil {
		t.Error("expected error for truncated header")
	}
	// header claims more bytes than present
	if _, err := decodePhoenixV2Push([]byte{3, 5, 5, 'a'}); err == nil {
		t.Error("expected error for truncated fields")
	}
	msg, err := decodePhoenixV2Push([]byte{2, 3, 5, 'j', '1', 't', 'o', 'p', 'e', 'v', 'e', 'n', 't', '{', '}'})
	if err != nil {
		t.Fatalf("decodePhoenixV2Push: %v", err)
	}
	if msg.JoinRef != "j1" || msg.Topic != "top" || msg.Event != "event" || string(msg.Payload) != "{}" {
		t.Errorf("unexpected msg: %+v", msg)
	}
}

func TestAppendPhoenixV2PushRejectsLongField(t *testing.T) {
	var buf bytes.Buffer
	err := appendPhoenixV2Push(&buf, strings.Repeat("t", 256), "ev", "j", "r", []byte("{}"))
	if err == nil {
		t.Fatal("expected field-length error")
	}
}

func TestEncodePhoenixV2PushRejectsLongField(t *testing.T) {
	if _, _, err := encodePhoenixV2Push("t", "ev", strings.Repeat("j", 256), "r", []byte("{}")); err == nil {
		t.Fatal("expected field-length error")
	}
}

func TestEncodePhoenixV2TextRejectsInvalidPayload(t *testing.T) {
	if _, _, err := encodePhoenixV2Text("t", "ev", "j", nil, []byte("{bad json")); err == nil {
		t.Fatal("expected JSON error for invalid payload")
	}
}

func TestDecodePhoenixMessageErrors(t *testing.T) {
	// Unknown message type.
	if _, err := decodePhoenixMessage(websocket.MessageType(99), []byte("x")); err == nil {
		t.Error("expected unknown-kind error")
	}
	// V2 text frame: malformed JSON.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`[`)); err == nil {
		t.Error("expected JSON error")
	}
	// Wrong field count.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`["j",null,"t"]`)); err == nil {
		t.Error("expected field-count error")
	}
	// Non-string join ref.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`[1,null,"t","e",{}]`)); err == nil {
		t.Error("expected join-ref error")
	}
	// Non-string ref.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`["j",5,"t","e",{}]`)); err == nil {
		t.Error("expected ref error")
	}
	// Non-string topic.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`["j",null,7,"e",{}]`)); err == nil {
		t.Error("expected topic error")
	}
	// Non-string event.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`["j",null,"t",9,{}]`)); err == nil {
		t.Error("expected event error")
	}
	// Legacy V1 object text frame still decodes.
	if _, err := decodePhoenixMessage(websocket.MessageText, []byte(`{"topic":"t","event":"e","payload":{}}`)); err != nil {
		t.Errorf("legacy V1 frame: %v", err)
	}
	// Empty binary frame.
	if _, err := decodePhoenixMessage(websocket.MessageBinary, nil); err == nil {
		t.Error("expected error for empty binary frame")
	}
	// Binary frame with unknown kind byte.
	if _, err := decodePhoenixMessage(websocket.MessageBinary, []byte{0xff, 0}); err == nil {
		t.Error("expected unknown-kind error")
	}
	// Truncated binary frames for each kind.
	for _, kind := range []byte{phoenixV2PushKind, phoenixV2ReplyKind, phoenixV2BroadcastKind} {
		if _, err := decodePhoenixMessage(websocket.MessageBinary, []byte{kind}); err == nil {
			t.Errorf("expected truncated-frame error for kind %d", kind)
		}
	}
}

func TestDecodePhoenixV2Reply(t *testing.T) {
	// Header claims fields beyond the buffer.
	if _, err := decodePhoenixV2Reply([]byte{9, 9, 9, 4, 'a', 'o', 'k'}); err == nil {
		t.Error("expected truncated-fields error")
	}
	msg, err := decodePhoenixV2Reply([]byte{1, 1, 1, 2, 'j', 'r', 't', 'o', 'k', '{', '}'})
	if err != nil {
		t.Fatalf("decodePhoenixV2Reply: %v", err)
	}
	if msg.Event != "phx_reply" || msg.Status != "ok" || msg.Ref == nil || *msg.Ref != "r" ||
		msg.JoinRef != "j" || msg.Topic != "t" || string(msg.Payload) != "{}" {
		t.Errorf("unexpected reply: %+v", msg)
	}
}

func TestDecodePhoenixV2Broadcast(t *testing.T) {
	if _, err := decodePhoenixV2Broadcast([]byte{8, 8, 'a'}); err == nil {
		t.Error("expected truncated-fields error")
	}
	msg, err := decodePhoenixV2Broadcast([]byte{4, 5, 't', 'o', 'p', 'i', 'e', 'v', 'e', 'n', 't', '{', '}'})
	if err != nil {
		t.Fatalf("decodePhoenixV2Broadcast: %v", err)
	}
	if msg.Topic != "topi" || msg.Event != "event" || string(msg.Payload) != "{}" {
		t.Errorf("unexpected broadcast: %+v", msg)
	}
}

func TestBatchableEvent(t *testing.T) {
	if !batchableEvent("trap", 10) {
		t.Error("trap should be batchable")
	}
	if batchableEvent("device_inventory", 10) {
		t.Error("unknown event should not be batchable")
	}
	if batchableEvent("trap", resultBatchFlushBytes) {
		t.Error("oversized payload should not be batchable")
	}
}

func TestResultPriority(t *testing.T) {
	if resultPriority("result", true) != 3 {
		t.Error("reserved results go to lane 3")
	}
	if resultPriority("trap", false) != 0 {
		t.Error("traps go to lane 0")
	}
	if resultPriority("check_result", false) != 1 {
		t.Error("check results go to lane 1")
	}
	if resultPriority("result", false) != 2 {
		t.Error("poll results go to lane 2")
	}
}

func TestNextResultFrameSelection(t *testing.T) {
	s := &session{resultBatches: true}
	big := resultBatchFlushBytes/2 + 1
	mk := func(event string, wire int, lane uint8) outbound {
		return outbound{event: event, payload: make(json.RawMessage, wire), lane: lane}
	}

	// Lane 0 preempts an empty batch; the bulk event is returned alone.
	lanes := &[4][]outbound{{mk("trap", 10, 0)}}
	got, event := s.nextResultFrame(lanes, false)
	if event != "trap" || len(got) != 1 || len(lanes[0]) != 0 {
		t.Errorf("lane 0 preemption: event=%q results=%d left=%d", event, len(got), len(lanes[0]))
	}

	// A non-batchable bulk head on a lower lane flushes the forming batch.
	lanes = &[4][]outbound{
		1: {mk("check_result", 10, 1)},
		2: {mk("discovery", big, 2), mk("result", 10, 2)},
	}
	got, event = s.nextResultFrame(lanes, false)
	if event != "check_result" || len(got) != 1 {
		t.Errorf("bulk preemption: event=%q results=%d", event, len(got))
	}
	if len(lanes[2]) != 2 || lanes[2][0].event != "discovery" {
		t.Errorf("bulk head must stay staged: %v", lanes[2])
	}

	// With no pending batch, the bulk head leaves alone.
	got, event = s.nextResultFrame(lanes, false)
	if event != "discovery" || len(got) != 1 || len(lanes[2]) != 1 {
		t.Errorf("bulk alone: event=%q results=%d left=%d", event, len(got), len(lanes[2]))
	}

	// Batch accumulates to the byte target and flushes on flushDue.
	half := resultBatchFlushBytes / 2
	lanes = &[4][]outbound{2: {mk("result", half, 2), mk("result", half, 2)}}
	got, event = s.nextResultFrame(lanes, false)
	if len(got) != 2 || event != "result" {
		t.Errorf("byte target flush: results=%d event=%q", len(got), event)
	}

	// A candidate that would overflow the target breaks the inner loop; the
	// forming batch is released on flushDue.
	chunk := resultBatchFlushBytes/2 - 30000
	lanes = &[4][]outbound{2: {mk("result", chunk, 2), mk("result", chunk, 2), mk("result", chunk, 2)}}
	got, event = s.nextResultFrame(lanes, true)
	if len(got) != 2 || event != "result" {
		t.Errorf("overflow break then flush: results=%d event=%q", len(got), event)
	}
	if len(lanes[2]) != 1 {
		t.Errorf("overflowing candidate must stay staged: %v", lanes[2])
	}

	// Below the target without flushDue the batch is unstaged.
	lanes = &[4][]outbound{2: {mk("result", 10, 2)}}
	got, event = s.nextResultFrame(lanes, false)
	if got != nil || event != "" {
		t.Errorf("held batch should return empty, got %d %q", len(got), event)
	}
	if len(lanes[2]) != 1 {
		t.Errorf("unstageBatch must restore the lane, got %v", lanes[2])
	}
	// flushDue releases the held batch.
	got, event = s.nextResultFrame(lanes, true)
	if len(got) != 1 || event != "result" {
		t.Errorf("flushDue release: results=%d event=%q", len(got), event)
	}

	// Empty lanes return nothing.
	empty := &[4][]outbound{}
	if got, event := s.nextResultFrame(empty, true); got != nil || event != "" {
		t.Errorf("empty lanes: results=%d event=%q", len(got), event)
	}
}

func TestHasRoomFor(t *testing.T) {
	// Channel-bounded mode: room depends on ingress channel occupancy.
	ch := newResultQueue(8)
	if !ch.hasRoomFor(1 << 20) {
		t.Error("channel-bounded queue must report room")
	}
	ch.items <- outbound{}
	ch.items = make(chan outbound, 1)
	ch.items <- outbound{}
	if ch.hasRoomFor(1) {
		t.Error("full ingress channel must report no room")
	}

	// Byte mode: channel occupancy then byte ceiling.
	q := newResultQueueForAgentBytes(context.Background(), 64)
	if !q.hasRoomFor(10) {
		t.Error("empty byte queue must report room")
	}
	q.byteUsage.Store(60)
	if q.hasRoomFor(10) {
		t.Error("byte ceiling must report no room")
	}
	q.byteUsage.Store(0)
	full := newResultQueueForAgentBytes(context.Background(), 1<<20)
	full.items = make(chan outbound, 1)
	full.items <- outbound{}
	if full.hasRoomFor(1) {
		t.Error("full byte-mode ingress must report no room")
	}
}

func TestPendingAckCount(t *testing.T) {
	q := newResultQueueForAgentBytes(context.Background(), 1<<20)
	r := outbound{event: "result", sequence: 7, protoPayload: []byte("x")}
	q.hold(r)
	if got := q.pendingAckCount(); got != 1 {
		t.Errorf("pendingAckCount = %d, want 1", got)
	}
}

func TestDecodeResultAckLanes(t *testing.T) {
	ack := &pb.AgentResultAck{CumulativeSequence: 9}
	raw, err := proto.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Raw-binary lane decodes the protobuf bytes directly.
	seq, ok := decodeResultAck(channelMsg{Binary: true, Payload: json.RawMessage(raw)})
	if !ok || seq != 9 {
		t.Errorf("binary lane: seq=%d ok=%v", seq, ok)
	}
	// Raw lane rejects garbage.
	if _, ok := decodeResultAck(channelMsg{Binary: true, Payload: json.RawMessage([]byte{0xff, 0xff})}); ok {
		t.Error("binary lane must reject undecodable payload")
	}
	// Raw lane rejects oversized payloads.
	big := make([]byte, maxDecodedJobPayloadBytes+1)
	if _, ok := decodeResultAck(channelMsg{Binary: true, Payload: json.RawMessage(big)}); ok {
		t.Error("binary lane must reject oversized payload")
	}
	// Text lane wants the base64 JSON object.
	payload, err := json.Marshal(map[string]string{"binary": "not-base64!"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeResultAck(channelMsg{Payload: payload}); ok {
		t.Error("text lane must reject bad base64")
	}
}

func TestWSDialKeepsExistingVSN(t *testing.T) {
	rawURL := "ws://example/agent?token=x&vsn=1.0.0"
	if got := withVSNQuery(rawURL); got != rawURL {
		t.Errorf("withVSNQuery rewrote an existing vsn param: %q", got)
	}
}

func TestWSWriteBinary(t *testing.T) {
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()
		kind, data, err := conn.Read(r.Context())
		if err == nil {
			if kind != websocket.MessageBinary {
				err = conn.Close(websocket.StatusProtocolError, "want binary")
			} else {
				err = conn.Write(r.Context(), kind, data)
			}
		}
		serverErr <- err
	}))
	defer srv.Close()

	ws, err := wsDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("wsDial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	want := []byte{0, 1, 2, 3}
	if err := ws.WriteBinary(context.Background(), want); err != nil {
		t.Fatalf("WriteBinary: %v", err)
	}
	kind, got, err := ws.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if kind != websocket.MessageBinary || !bytes.Equal(got, want) {
		t.Fatalf("echo = kind %d %v", kind, got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestExecuteMikrotikJobDeadline(t *testing.T) {
	out := newResultQueueForAgentBytes(context.Background(), 1<<20)
	job := &pb.AgentJob{
		JobId:     "deadline-job",
		DeadlineMs: 1,
		MikrotikDevice: &pb.MikrotikDevice{
			Ip:       "127.0.0.1",
			Port:     1, // nothing listens; dial fails fast
			Username: "u",
			Password: "p",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	executeMikrotikJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "mikrotik_result" {
			t.Errorf("event = %q, want mikrotik_result", res.event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no mikrotik result enqueued")
	}
}
