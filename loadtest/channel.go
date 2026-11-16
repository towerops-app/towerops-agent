// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package loadtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// Capability tokens this stub confirms to a modern agent.
const (
	capabilityInventoryUpdate = "inventory_update_v1"
	capabilityResultBatch     = "result_batch_v1"
	capabilityResultAck       = "result_ack_v1"
)

// serverCapabilities is the authoritative set sent in the join reply. With
// them the agent switches to Phoenix serializer V2, AgentInventoryUpdate
// chunks and result_batch/result_ack.
func serverCapabilities() []string {
	return []string{capabilityInventoryUpdate, capabilityResultBatch, capabilityResultAck}
}

// ChannelOptions configures the stub channel server.
type ChannelOptions struct {
	Jobs     []*pb.AgentJob
	Revision uint64
	// ChunkJobs bounds jobs per full-sync chunk. The compact column form
	// keeps a 3,000-device chunk small; the bound still keeps every frame
	// well below the agent's 10 MiB inbound cap if a legacy build is used.
	ChunkJobs int
	// UplinkBytesPerSec throttles bytes read from the agent. 125_000 models
	// the documented 1 Mbps floor; zero disables throttling.
	UplinkBytesPerSec int
}

// ChannelServer is the stub Phoenix channel: it accepts the agent's join,
// pushes the inventory, consumes result frames and models deliberate
// WebSocket outages and a shaped uplink. It speaks the legacy JSON/base64
// envelope and the Phoenix binary V2 frame format.
type ChannelServer struct {
	opts ChannelOptions

	listener net.Listener
	baseURL  string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	activeMu sync.Mutex
	active   map[*websocket.Conn]struct{}

	joins      atomic.Int64
	disconnect atomic.Int64
	applied    atomic.Uint64
	dropUntil  atomic.Int64
	ledger     atomic.Pointer[ResultLedger]

	lagKeys atomic.Pointer[map[string]lagKey]
}

// lagKey maps a server-side result key back to the job whose wall-clock phase
// produced it, so arrivals can be scored against their planned tick.
type lagKey struct {
	jobID    string
	interval time.Duration
}

// StartChannelServer binds the loopback HTTP listener and serves until Stop.
func StartChannelServer(ctx context.Context, opts ChannelOptions) (*ChannelServer, error) {
	if len(opts.Jobs) == 0 {
		return nil, errors.New("loadtest: channel server needs jobs")
	}
	if opts.ChunkJobs <= 0 {
		opts.ChunkJobs = 500
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen stub channel: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s := &ChannelServer{
		opts:     opts,
		listener: listener,
		baseURL:  "ws://" + listener.Addr().String(),
		ctx:      runCtx,
		cancel:   cancel,
		active:   make(map[*websocket.Conn]struct{}),
	}
	s.buildLagKeys()

	mux := http.NewServeMux()
	mux.HandleFunc("/socket/agent/websocket", s.handleWebSocket)
	httpServer := &http.Server{Handler: mux}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = httpServer.Serve(listener)
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-runCtx.Done()
		_ = httpServer.Close()
	}()
	s.ledger.Store(NewResultLedger())
	return s, nil
}

// Stop ends the listener and every live connection.
func (s *ChannelServer) Stop() {
	s.cancel()
	s.closeActive()
	_ = s.listener.Close()
	s.wg.Wait()
}

// BaseURL is the ws:// base the harness dials.
func (s *ChannelServer) BaseURL() string { return s.baseURL }

// Joins counts accepted phx_join exchanges.
func (s *ChannelServer) Joins() int64 { return s.joins.Load() }

// Disconnects counts deliberate outage closures.
func (s *ChannelServer) Disconnects() int64 { return s.disconnect.Load() }

// RevisionApplied reports whether a heartbeat echoed the pushed revision.
func (s *ChannelServer) RevisionApplied() bool {
	return s.opts.Revision == 0 || s.applied.Load() >= s.opts.Revision
}

// Ledger returns the active result ledger.
func (s *ChannelServer) Ledger() *ResultLedger { return s.ledger.Load() }

// ResetLedger starts a fresh measurement window.
func (s *ChannelServer) ResetLedger() { s.ledger.Store(NewResultLedger()) }

// StartDrop closes every connection and refuses new joins for the duration.
func (s *ChannelServer) StartDrop(duration time.Duration) {
	s.dropUntil.Store(time.Now().Add(duration).UnixNano())
	s.disconnect.Add(1)
	s.closeActive()
}

// Dropping reports whether the outage window is still active.
func (s *ChannelServer) Dropping() bool {
	return time.Now().UnixNano() < s.dropUntil.Load()
}

func (s *ChannelServer) closeActive() {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	for conn := range s.active {
		_ = conn.CloseNow()
	}
	clear(s.active)
}

func (s *ChannelServer) addActive(conn *websocket.Conn) {
	s.activeMu.Lock()
	s.active[conn] = struct{}{}
	s.activeMu.Unlock()
}

func (s *ChannelServer) removeActive(conn *websocket.Conn) {
	s.activeMu.Lock()
	delete(s.active, conn)
	s.activeMu.Unlock()
}

func (s *ChannelServer) buildLagKeys() {
	keys := make(map[string]lagKey)
	for _, job := range s.opts.Jobs {
		if job == nil {
			continue
		}
		interval := time.Duration(job.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		switch job.JobType {
		case pb.JobType_POLL, pb.JobType_DISCOVER:
			keys["snmp:"+job.JobId] = lagKey{jobID: job.JobId, interval: interval}
		case pb.JobType_PING:
			keys["ping:"+job.DeviceId] = lagKey{jobID: job.JobId, interval: interval}
		}
	}
	s.lagKeys.Store(&keys)
}

// throttledResponseWriter gives Accept a hijacker whose TCP reads carry the
// configured byte ceiling. Blocking reads are how a server models a slow
// uplink: the client's writes back up and its write deadlines then see the
// same wall time a real 1 Mbps path would produce.
type throttledResponseWriter struct {
	http.ResponseWriter
	bytesPerSec int
}

func (w *throttledResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("loadtest: response writer cannot hijack")
	}
	tcp, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	// The HTTP response went through the original writer; flush it before
	// swapping the socket for the throttled wrapper.
	if buffered != nil {
		if err := buffered.Flush(); err != nil {
			return nil, nil, err
		}
	}
	conn := newThrottledConn(tcp, w.bytesPerSec)
	return conn, bufio.NewReadWriter(buffered.Reader, bufio.NewWriter(conn)), nil
}

// throttledConn is a token-bucket wrapper around one TCP connection.
type throttledConn struct {
	net.Conn
	bytesPerSec int
	budget      float64
	last        time.Time
	mu          sync.Mutex
}

func newThrottledConn(conn net.Conn, bytesPerSec int) *throttledConn {
	return &throttledConn{
		Conn:        conn,
		bytesPerSec: bytesPerSec,
		budget:      float64(bytesPerSec),
		last:        time.Now(),
	}
}

// Read admits at most the accumulated byte budget per call and sleeps until
// the next byte is affordable. Reads are serialized by the WebSocket reader.
func (c *throttledConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(c.last).Seconds()
	c.last = now
	c.budget = min(float64(c.bytesPerSec), c.budget+elapsed*float64(c.bytesPerSec))
	if c.budget < 1 {
		wait := time.Duration((1 - c.budget) / float64(c.bytesPerSec) * float64(time.Second))
		refillFrom := c.last
		c.mu.Unlock()
		time.Sleep(wait)
		c.mu.Lock()
		c.last = time.Now()
		c.budget = min(float64(c.bytesPerSec),
			c.budget+c.last.Sub(refillFrom).Seconds()*float64(c.bytesPerSec))
	}
	if len(p) == 0 {
		c.mu.Unlock()
		return 0, nil
	}
	n := min(len(p), 16<<10, int(c.budget))
	if n < 1 {
		n = 1
	}
	c.budget -= float64(n)
	c.mu.Unlock()
	return c.Conn.Read(p[:n])
}

func (s *ChannelServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.Dropping() {
		http.Error(w, "stub channel outage", http.StatusServiceUnavailable)
		return
	}

	response := http.ResponseWriter(w)
	if s.opts.UplinkBytesPerSec > 0 {
		response = &throttledResponseWriter{ResponseWriter: w, bytesPerSec: s.opts.UplinkBytesPerSec}
	}
	accept := &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover}
	conn, err := websocket.Accept(response, r, accept)
	if err != nil {
		return
	}
	s.addActive(conn)
	defer s.removeActive(conn)

	connCtx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	go func() {
		<-connCtx.Done()
		_ = conn.CloseNow()
	}()

	// The agent opens with a Phoenix V2 JSON-array phx_join.
	kind, data, err := readOneMessage(connCtx, conn)
	if err != nil {
		return
	}
	join, _ := unmarshalFrame(kind, data)
	if join.event != "phx_join" {
		return
	}
	s.joins.Add(1)
	if err := s.sendJoinReply(conn, join.topic, join.ref, agentCapabilities(join)); err != nil {
		return
	}
	v2 := len(agentCapabilities(join)) > 0
	if err := s.sendInventory(conn, v2, join.topic); err != nil {
		slog.Error("stub channel inventory failed", "error", err)
		return
	}

	for {
		kind, data, err := readOneMessage(connCtx, conn)
		if err != nil {
			return
		}
		frame, isBinary := unmarshalFrame(kind, data)
		if frame.event == "" {
			continue
		}
		switch frame.event {
		case "heartbeat":
			if frame.topic == "phoenix" {
				// Channel heartbeat: Phoenix answers the client's ref.
				if frame.ref != nil {
					_ = s.sendJSONReply(conn, "phoenix", frame.ref)
				}
				continue
			}
			s.handleAgentHeartbeat(frame)
		case "result_batch":
			if err := s.handleResultBatch(conn, isBinary, frame); err != nil {
				slog.Error("stub channel result batch failed", "error", err)
				return
			}
		default:
			s.handleResultEvent(frame)
		}
	}
}

// agentCapabilities reads the capability tokens the agent sent in its join.
func agentCapabilities(join inboundFrame) []string {
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(join.payload, &payload); err != nil {
		return nil
	}
	var confirmed []string
	for _, capability := range serverCapabilities() {
		if slices.Contains(payload.Capabilities, capability) {
			confirmed = append(confirmed, capability)
		}
	}
	return confirmed
}

// readOneMessage reads one complete WebSocket message with a bounded lifetime.
func readOneMessage(ctx context.Context, conn *websocket.Conn) (websocket.MessageType, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return conn.Read(ctx)
}

// inboundFrame is the transport-independent channel message.
type inboundFrame struct {
	joinRef    string
	ref        *string
	topic      string
	event      string
	payload    json.RawMessage
	rawPayload []byte // untouched payload bytes on a V2 binary frame
}

// unmarshalFrame parses by websocket message kind: V2 text arrays, legacy V1
// objects on text, and Phoenix V2 binary frames on binary.
func unmarshalFrame(kind websocket.MessageType, data []byte) (inboundFrame, bool) {
	switch kind {
	case websocket.MessageText:
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var fields []json.RawMessage
			if err := json.Unmarshal(trimmed, &fields); err != nil || len(fields) != 5 {
				return inboundFrame{}, false
			}
			frame := inboundFrame{}
			_ = json.Unmarshal(fields[0], &frame.joinRef)
			if string(fields[1]) != "null" {
				var ref string
				if err := json.Unmarshal(fields[1], &ref); err != nil {
					return inboundFrame{}, false
				}
				frame.ref = &ref
			}
			if err := json.Unmarshal(fields[2], &frame.topic); err != nil {
				return inboundFrame{}, false
			}
			if err := json.Unmarshal(fields[3], &frame.event); err != nil {
				return inboundFrame{}, false
			}
			frame.payload = append(json.RawMessage(nil), fields[4]...)
			return frame, true
		}
		var msg channelWire
		if err := json.Unmarshal(data, &msg); err != nil {
			return inboundFrame{}, false
		}
		return inboundFrame{
			ref:     msg.Ref,
			topic:   msg.Topic,
			event:   msg.Event,
			payload: msg.Payload,
		}, false
	case websocket.MessageBinary:
		if len(data) == 0 || data[0] != 0 {
			return inboundFrame{}, false
		}
		frame, err := decodeBinaryClientPush(data[1:])
		if err != nil {
			return inboundFrame{}, false
		}
		return frame, true
	default:
		return inboundFrame{}, false
	}
}

// decodeBinaryClientPush parses the client push form after its kind byte:
// join_ref/ref/topic/event lengths, then those strings and the payload.
func decodeBinaryClientPush(data []byte) (inboundFrame, error) {
	if len(data) < 4 {
		return inboundFrame{}, errors.New("truncated V2 header")
	}
	joinSize, refSize, topicSize, eventSize := int(data[0]), int(data[1]), int(data[2]), int(data[3])
	rest := data[4:]
	if len(rest) < joinSize+refSize+topicSize+eventSize {
		return inboundFrame{}, errors.New("truncated V2 header")
	}
	at := 0
	take := func(size int) string {
		value := string(rest[at : at+size])
		at += size
		return value
	}
	joinRef := take(joinSize)
	ref := take(refSize)
	topic := take(topicSize)
	event := take(eventSize)
	frame := inboundFrame{joinRef: joinRef, topic: topic, event: event, rawPayload: rest[at:]}
	if ref != "" {
		refValue := ref
		frame.ref = &refValue
	}
	return frame, nil
}

// channelWire matches the agent's JSON envelope.
type channelWire struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
}

// binaryEnvelope wraps protobuf bytes in the agent's stable JSON payload
// shape. V2 without capability lanes still uses this application envelope.
func binaryEnvelope(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	out := make([]byte, 0, len(encoded)+len(`{"binary":""}`))
	out = append(out, `{"binary":"`...)
	out = append(out, encoded...)
	out = append(out, `"}`...)
	return out
}

// payloadProto extracts the protobuf bytes from an inbound application
// payload: raw bytes on a Phoenix V2 binary frame, the JSON binary envelope
// on legacy and capability-less V2 text frames.
func payloadProto(frame inboundFrame) ([]byte, error) {
	if frame.rawPayload != nil {
		return frame.rawPayload, nil
	}
	if len(frame.payload) == 0 {
		return nil, nil
	}
	return decodeBinaryEnvelope(frame.payload)
}

// decodeBinaryEnvelope accepts the {"binary":"..."} object and, for
// compatibility with the very first legacy shape, a bare base64 string.
func decodeBinaryEnvelope(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '"' {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(encoded)
	}
	var envelope struct {
		Binary string `json:"binary"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(envelope.Binary)
}

func (s *ChannelServer) handleAgentHeartbeat(frame inboundFrame) {
	payload, err := payloadProto(frame)
	if err != nil || len(payload) == 0 {
		return
	}
	var hb pb.AgentHeartbeat
	if err := proto.Unmarshal(payload, &hb); err != nil {
		return
	}
	if hb.AppliedRevision > 0 {
		s.applied.Store(hb.AppliedRevision)
	}
}

// resultEnvelope is one entry of a result_batch frame.
type resultEnvelope struct {
	event    string
	payload  []byte
	sequence uint64
}

func decodeResultBatch(payload []byte) ([]resultEnvelope, error) {
	var batch pb.AgentResultBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		return nil, fmt.Errorf("decode AgentResultBatch: %w", err)
	}
	envelopes := make([]resultEnvelope, 0, len(batch.Results))
	for _, result := range batch.Results {
		if result == nil {
			continue
		}
		envelopes = append(envelopes, resultEnvelope{
			event:    result.Event,
			payload:  append([]byte(nil), result.Payload...),
			sequence: result.Sequence,
		})
	}
	return envelopes, nil
}

func (s *ChannelServer) handleResultBatch(conn *websocket.Conn, isBinary bool, frame inboundFrame) error {
	// result_batch_v1 over V2 carries raw protobuf; keep the legacy JSON
	// binary-envelope path for compatibility builds.
	var (
		payload []byte
		err     error
	)
	if frame.rawPayload != nil {
		payload = frame.rawPayload
	} else {
		payload, err = payloadProto(frame)
	}
	if err != nil {
		return fmt.Errorf("batch payload: %w", err)
	}
	envelopes, err := decodeResultBatch(payload)
	if err != nil {
		return err
	}
	ledger := s.ledger.Load()
	now := time.Now()
	for _, envelope := range envelopes {
		var inner []byte
		var err error
		if isBinary {
			// A raw capability batch carries raw protobuf in every envelope.
			inner = envelope.payload
		} else {
			inner, err = decodeBinaryEnvelope(envelope.payload)
		}
		if err != nil {
			ledger.RecordError(&pb.AgentError{Message: "undecodable batch envelope: " + err.Error()})
			continue
		}
		s.recordEnvelope(ledger, now, envelope.event, inner)
	}
	return s.sendResultAck(conn, isBinary, frame.topic, envelopes)
}

// sendResultAck emits the cumulative AgentResultAck for one batch. The
// negotiated V2 capability lane carries raw protobuf; the legacy JSON path
// keeps the binary envelope.
func (s *ChannelServer) sendResultAck(conn *websocket.Conn, isBinary bool, topic string, envelopes []resultEnvelope) error {
	if len(envelopes) == 0 {
		return nil
	}
	payload, err := proto.Marshal(&pb.AgentResultAck{
		CumulativeSequence: envelopes[len(envelopes)-1].sequence,
	})
	if err != nil {
		return fmt.Errorf("marshal AgentResultAck: %w", err)
	}
	if !isBinary {
		return s.sendPush(conn, false, topic, "result_ack", payload)
	}
	return s.sendPush(conn, true, topic, "result_ack", payload)
}

func (s *ChannelServer) recordEnvelope(ledger *ResultLedger, now time.Time, event string, payload []byte) {
	switch event {
	case "result":
		var msg pb.SnmpResult
		if err := proto.Unmarshal(payload, &msg); err != nil {
			ledger.RecordError(&pb.AgentError{Message: "undecodable SnmpResult: " + err.Error()})
			return
		}
		key := "snmp:" + msg.JobId
		sequence := msg.Sequence
		if sequence == 0 {
			sequence = 1
		}
		ledger.Record(ResultRecord{
			Key:      key,
			Sequence: sequence,
			Final:    msg.Final || msg.Sequence == 0,
			Partial:  msg.Partial,
			Arrived:  now,
			Lag:      s.lagFor(key, now),
		})
	case "monitoring_check":
		var msg pb.MonitoringCheck
		if err := proto.Unmarshal(payload, &msg); err != nil {
			ledger.RecordError(&pb.AgentError{Message: "undecodable MonitoringCheck: " + err.Error()})
			return
		}
		key := "ping:" + msg.DeviceId
		ledger.Record(ResultRecord{Key: key, Sequence: 1, Final: true, Arrived: now, Lag: s.lagFor(key, now)})
	case "error":
		var msg pb.AgentError
		if err := proto.Unmarshal(payload, &msg); err == nil {
			ledger.RecordError(&msg)
		}
	default:
		ledger.Record(ResultRecord{Key: "unknown:" + event, Final: true, Arrived: now})
	}
}

func (s *ChannelServer) handleResultEvent(frame inboundFrame) {
	payload, err := payloadProto(frame)
	if err != nil {
		return
	}
	s.recordEnvelope(s.ledger.Load(), time.Now(), frame.event, payload)
}

func (s *ChannelServer) lagFor(key string, now time.Time) time.Duration {
	keys := s.lagKeys.Load()
	if keys == nil {
		return 0
	}
	lk, ok := (*keys)[key]
	if !ok {
		return 0
	}
	return now.Sub(ScenarioSchedulePhase(lk.jobID, lk.interval, now))
}

// sendJoinReply returns the Phoenix ok reply plus the capabilities the agent
// offered and this stub supports. An empty list keeps the legacy path.
func (s *ChannelServer) sendJoinReply(conn *websocket.Conn, topic string, ref *string, capabilities []string) error {
	response := map[string]any{}
	if len(capabilities) > 0 {
		response["capabilities"] = capabilities
	}
	payload, _ := json.Marshal(map[string]any{"status": "ok", "response": response})
	msg := channelWire{Topic: topic, Event: "phx_reply", Payload: payload, Ref: ref}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, data)
}

// sendJSONReply answers a control ref with a plain Phoenix ok reply.
func (s *ChannelServer) sendJSONReply(conn *websocket.Conn, topic string, ref *string) error {
	return s.sendJoinReply(conn, topic, ref, nil)
}

// sendPush sends an application event. Binary capability frames carry raw
// protobuf in Phoenix's server-push form; text frames carry the base64 JSON
// object in either the V2 array or legacy object envelope.
func (s *ChannelServer) sendPush(conn *websocket.Conn, isBinary bool, topic, event string, payload []byte) error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if isBinary {
		frame := encodeBinaryServerPush(topic, event, payload)
		return conn.Write(ctx, websocket.MessageBinary, frame)
	}
	envelope := binaryEnvelope(payload)
	msg := channelWire{Topic: topic, Event: event, Payload: json.RawMessage(envelope)}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}

// encodeBinaryServerPush writes kind byte 0 and the no-ref server-push layout:
// join_ref/topic/event lengths, then those strings and raw protobuf payload.
func encodeBinaryServerPush(topic, event string, payload []byte) []byte {
	out := make([]byte, 0, 4+len(topic)+len(event)+len(payload))
	out = append(out, 0)
	out = append(out, byte(0), byte(len(topic)), byte(len(event)))
	out = append(out, topic...)
	out = append(out, event...)
	out = append(out, payload...)
	return out
}

// sendInventory pushes the authoritative inventory. A modern agent gets
// chunked AgentInventoryUpdate full syncs; the fallback still speaks the
// legacy jobs frame for protocol compatibility.
func (s *ChannelServer) sendInventory(conn *websocket.Conn, modern bool, topic string) error {
	if modern {
		// The capability reply makes this agent a V2 peer; use V2 from the
		// first push rather than waiting for an inbound binary frame.
		return s.sendInventoryUpdate(conn, true, topic)
	}
	return s.sendLegacyJobs(conn, topic)
}

func (s *ChannelServer) sendInventoryUpdate(conn *websocket.Conn, isBinary bool, topic string) error {
	jobs := s.opts.Jobs
	chunks := max(1, (len(jobs)+s.opts.ChunkJobs-1)/s.opts.ChunkJobs)
	for chunk := 1; chunk <= chunks; chunk++ {
		start := (chunk - 1) * s.opts.ChunkJobs
		end := min(len(jobs), start+s.opts.ChunkJobs)
		update := &pb.AgentInventoryUpdate{
			Revision:   s.opts.Revision,
			Upserts:    jobs[start:end],
			FullSync:   true,
			ChunkIndex: uint32(chunk),
			ChunkCount: uint32(chunks),
		}
		payload, err := proto.Marshal(update)
		if err != nil {
			return fmt.Errorf("marshal AgentInventoryUpdate: %w", err)
		}
		if err := s.sendPush(conn, isBinary, topic, "inventory_update", payload); err != nil {
			return fmt.Errorf("push inventory chunk %d/%d: %w", chunk, chunks, err)
		}
	}
	return nil
}

// sendLegacyJobs sends the old AgentJobList frame with every compact query
// expanded to explicit OIDs. This is the protocol-compatibility path: modern
// agents keep the 10-column form, while an old agent receives exactly the
// 300 leaves it knows how to poll.
func (s *ChannelServer) sendLegacyJobs(conn *websocket.Conn, topic string) error {
	jobs := make([]*pb.AgentJob, 0, len(s.opts.Jobs))
	for _, job := range s.opts.Jobs {
		if job == nil {
			continue
		}
		legacy := proto.Clone(job).(*pb.AgentJob)
		for _, query := range legacy.Queries {
			if len(query.Oids) == 0 {
				query.Oids = expandColumnOIDs(query.OidColumns, query.OidIndexes)
			}
		}
		jobs = append(jobs, legacy)
	}
	list := &pb.AgentJobList{Jobs: jobs, Revision: s.opts.Revision}
	payload, err := proto.Marshal(list)
	if err != nil {
		return fmt.Errorf("marshal AgentJobList: %w", err)
	}
	return s.sendPush(conn, false, topic, "jobs", payload)
}

// expandColumnOIDs performs the legacy OID expansion locally. Agent-side
// expansion deduplicates, so populating Oids only on the legacy path keeps
// modern inventory chunks compact.
func expandColumnOIDs(columns []string, indexes []uint32) []string {
	if len(columns) == 0 || len(indexes) == 0 {
		return nil
	}
	oids := make([]string, 0, len(columns)*len(indexes))
	for _, column := range columns {
		column = strings.TrimSuffix(column, ".")
		for _, index := range indexes {
			if column != "" && index != 0 {
				oids = append(oids, fmt.Sprintf("%s.%d", column, index))
			}
		}
	}
	return oids
}

// ResultRecord is one server-side observation of a result frame.
type ResultRecord struct {
	Key      string
	Sequence uint32
	Final    bool
	Partial  bool
	Arrived  time.Time
	Lag      time.Duration
}

// resultState accumulates frames for one logical result.
type resultState struct {
	frames   map[uint32]int
	arrivals []time.Time
	lags     []time.Duration
	maxSeq   uint32
	final    bool
	partial  bool
}

// complete reports whether the final frame arrived and, for split results,
// every lower-numbered frame was also observed.
func (s *resultState) complete() bool {
	if !s.final {
		return false
	}
	if s.maxSeq <= 1 {
		return true
	}
	for sequence := uint32(1); sequence <= s.maxSeq; sequence++ {
		if s.frames[sequence] == 0 {
			return false
		}
	}
	return true
}

// ResultLedger tracks every result identity the stub channel saw. The
// benchmark turns it into the pass/fail report; duplicates from a reconnect
// are expected and never count as drops.
type ResultLedger struct {
	mu     sync.Mutex
	byKey  map[string]*resultState
	errors []*pb.AgentError
}

// NewResultLedger returns an empty ledger.
func NewResultLedger() *ResultLedger {
	return &ResultLedger{byKey: make(map[string]*resultState)}
}

// Record adds one frame observation.
func (l *ResultLedger) Record(record ResultRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.byKey[record.Key]
	if state == nil {
		state = &resultState{frames: make(map[uint32]int)}
		l.byKey[record.Key] = state
	}
	state.frames[record.Sequence]++
	if record.Sequence > state.maxSeq {
		state.maxSeq = record.Sequence
	}
	state.arrivals = append(state.arrivals, record.Arrived)
	if record.Final {
		state.final = true
		state.lags = append(state.lags, record.Lag)
	}
	if record.Partial {
		state.partial = true
	}
}

// RecordError stores an agent error notice.
func (l *ResultLedger) RecordError(err *pb.AgentError) {
	l.mu.Lock()
	l.errors = append(l.errors, err)
	l.mu.Unlock()
}

// LedgerReport is the point-in-time evaluation of the ledger.
type LedgerReport struct {
	ReceivedResults uint64
	CompletedKeys   uint64
	MissingKeys     []string
	PartialResults  uint64
	AgentErrors     []string
	LagP95          time.Duration
	LagSamples      int
}

// Evaluate scores the ledger against every expected result key. Expected
// values are human-readable labels used in failure output.
func (l *ResultLedger) Evaluate(expected map[string]string) LedgerReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	report := LedgerReport{}
	for _, state := range l.byKey {
		report.ReceivedResults += uint64(len(state.arrivals))
		if state.complete() {
			report.CompletedKeys++
		}
		if state.partial {
			report.PartialResults++
		}
	}
	for key, label := range expected {
		state, ok := l.byKey[key]
		if !ok || !state.complete() {
			report.MissingKeys = append(report.MissingKeys, label+" ("+key+")")
		}
	}
	slices.Sort(report.MissingKeys)
	for _, err := range l.errors {
		report.AgentErrors = append(report.AgentErrors,
			fmt.Sprintf("%s/%s: %s", err.DeviceId, err.JobId, err.Message))
	}
	slices.Sort(report.AgentErrors)
	report.LagP95, report.LagSamples = l.lagP95()
	return report
}

func (l *ResultLedger) lagP95() (time.Duration, int) {
	var samples []time.Duration
	for _, state := range l.byKey {
		samples = append(samples, state.lags...)
	}
	if len(samples) == 0 {
		return 0, 0
	}
	slices.Sort(samples)
	index := len(samples) * 95 / 100
	if index >= len(samples) {
		index = len(samples) - 1
	}
	return samples[index], len(samples)
}
