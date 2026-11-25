// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

var doSelfUpdate = selfUpdateContext
var getHostname = os.Hostname
var decodeBase64 = base64.StdEncoding.DecodeString
var netInterfaces = net.Interfaces
var interfaceAddrs = (*net.Interface).Addrs

var errRestartRequested = errors.New("restart requested")
var errChannelReloaded = errors.New("channel reloaded")
var errSessionCancelled = errors.New("session cancelled")

// errSelfUpdateAborted ends a session whose self-update drain ran but whose
// re-exec never happened. The drain closed the scheduler and stopped job
// intake for good, so the only way back to a working session is a fresh one.
var errSelfUpdateAborted = errors.New("self-update aborted after drain")

// drainedSession is the session a self-update drain stopped, if any. When
// the update returns — exec failed, so the process is still this one — that
// session is ended so the reconnect rebuilds its scheduler and pools.
var drainedSession atomic.Pointer[session]
var joinTimeout = 10 * time.Second
var heartbeatInterval = 60 * time.Second
var channelHeartbeatInterval = 25 * time.Second
var initialRetryDelay = time.Second
var writeQueueTimeout = 5 * time.Second

var agentIDCounter atomic.Uint64
var processStart = time.Now()

// successfulConnectionThreshold is how long a session must last before the
// reconnect backoff is considered stale and reset to initialRetryDelay.
var successfulConnectionThreshold = 30 * time.Second

// maxRetryDelay caps the exponential ceiling the reconnect loop draws its
// wait under for repeated failures.
var maxRetryDelay = time.Minute

// A refusal the server cannot heal on its own (join rejected, HTTP 401 or
// 403 on the upgrade) draws from [minRefusalDelay, maxRefusalDelay): still
// retried, since an operator may fix the credential, but far below the
// rate a transient outage earns.
var minRefusalDelay = time.Minute
var maxRefusalDelay = 5 * time.Minute

// poolShutdownTimeout bounds how long session teardown waits for worker pools
// to drain before abandoning their in-flight jobs.
var poolShutdownTimeout = 5 * time.Second

const maxDecodedJobPayloadBytes = 10 << 20

var maxEncodedJobPayloadBytes = base64.StdEncoding.EncodedLen(maxDecodedJobPayloadBytes)

// resultQueueSize bounds the process-wide in-memory result backlog retained
// across WebSocket reconnects. It exceeds the 420 slots the former per-type
// result queues held together.
const resultQueueSize = 512

// overloadNoticeQueueSize bounds best-effort pool rejection notices separately
// from completed results, so a large job push cannot consume the result spool.
const overloadNoticeQueueSize = 64

// channelMsg is the WebSocket channel message format. V1 frames are the JSON
// envelope; Phoenix V2 binary frames are decoded into the same shape, with
// JoinRef recording the frame's join_ref. Capability-lane payloads on a V2
// transport are raw protobuf bytes; every other payload keeps the
// `%{binary: base64}` JSON object shape.
type channelMsg struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
	// JoinRef is only populated when decoding a Phoenix V2 binary frame.
	JoinRef string `json:"-"`
	// Status carries V2 binary reply's separate status field.
	Status string `json:"-"`
	// Binary records websocket.MessageBinary dispatch for raw capability
	// lanes. V2 text arrays carrying base64 JSON must remain non-binary.
	Binary bool `json:"-"`
}
type writeRequest struct {
	data []byte
	ack  chan error
	// buf is the pooled frame buffer data was built in, returned to the
	// pool once the write completes; nil for frames not built by
	// marshalChannelFrame.
	buf *bytes.Buffer
	// binary selects the Phoenix V2 binary serializer for this frame.
	binary bool
}

// inFlightWrite is a result frame handed to the writer but not yet
// acknowledged. The session loop keeps at most one so wire order is
// preserved, but it services other events while the write is in flight.
// results carries every result of the frame: one for a single-frame send,
// several for a "result_batch".
type inFlightWrite struct {
	result outbound
	// results is non-empty for batched sends and duplicates result as its
	// first element, so single-result code paths keep working unchanged.
	results []outbound
	event   string
	ack     chan error
	ref     string
	binary  bool
	// A reply can arrive before the writer's acknowledgment. Delay handling
	// it until the spool slot is released so a retry can reuse that capacity.
	reply *channelMsg
	// spooled means the results hold resultQueue capacity the loop must
	// release on success (legacy) or leave for the server ack (V1-ack mode);
	// notices carry no capacity.
	spooled bool
}

// pendingResult is a spooled result awaiting the server's phx_reply. The
// server only replies to rejected messages (oversized payloads), so entries
// are pruned by age rather than removed on success.
type pendingResult struct {
	result outbound
	// results holds every result of a batch frame; nil for single sends.
	results []outbound
	// sentAt stays zero until the writer acknowledges completion.
	sentAt time.Time
	// seq orders insertions; the count cap evicts the lowest.
	seq uint64
}

// pendingReplyTTL expires phx_reply tracking for results the server never
// answered. Successful handle_in calls produce no reply, so entries would
// otherwise accumulate for the life of the session.
var pendingReplyTTL = 30 * time.Second

// maxPendingResults caps pending by count. Every entry holds its result's
// payload, and a fast uplink acks far more than the spool's 512 slots within
// one TTL; without the cap that memory sits outside the spool's bound.
const maxPendingResults = resultQueueSize

// overloadRetryDelay spaces the retry of a result the server rejected as
// "overloaded". Its ingest queue is full, so an immediate re-send lands on
// the same full queue and the second rejection drops the result.
var overloadRetryDelay = 5 * time.Second

// runAgentWithScheduling connects to the server and runs the event loop with
// reconnect. traps may be nil when the trap listener is disabled.
//
// The recurring inventory, scheduler and worker pools live in a process
// poller that survives transport disconnects for the configured grace period
// (C1/D2). Only a grace expiry or a drained self-update rebuilds it; the
// result spool survives every rebuild so finished work is still replayed.
func runAgentWithScheduling(
	ctx context.Context,
	wsURL, token string,
	traps <-chan *pb.SnmpTrap,
	localScheduling bool,
) {
	// If this process booted into an unproven self-update, arm the startup
	// guard before anything else runs: a build that cannot reach its channel
	// gets its predecessor restored instead of crash-looping (issue #2736).
	_ = checkPendingUpdate()

	results := newResultQueueForAgentBytes(ctx, resultSpoolByteLimit())
	stopJobSummary := startJobSummaryLogger(ctx)
	defer stopJobSummary()
	// backoff is the ceiling the next retry draws under, not the wait
	// itself: reconnectDelay jitters inside it so a fleet dropped at once
	// does not redial in the same second.
	backoff := initialRetryDelay

	var poller *processPoller
	defer func() {
		if poller != nil {
			poller.stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if poller == nil || poller.stopped.Load() {
			if poller != nil {
				// stop() runs on the grace-timer goroutine and outlives the
				// stopped flag by the whole pool drain. Wait for it so the
				// new poller never schedules onto the old ping engine or has
				// its load hook blanked by the old stop().
				select {
				case <-poller.stopDone:
				case <-ctx.Done():
					return
				}
			}
			poller = newProcessPoller(ctx, results, localScheduling)
		}

		sessionStart := time.Now()
		err := runSessionWithPoller(
			ctx,
			wsURL,
			token,
			traps,
			results,
			poller,
		)
		sessionDuration := time.Since(sessionStart)

		// Reset the ceiling if the session ran successfully for a while
		// (indicates stable connection).
		healthy := sessionDuration >= successfulConnectionThreshold
		if healthy {
			slog.Debug("resetting reconnect backoff after successful session",
				"duration", sessionDuration,
				"previous_delay", backoff)
			backoff = initialRetryDelay
		}

		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRestartRequested) || errors.Is(err, errSelfUpdateAborted) {
			slog.Info("restart requested, reconnecting immediately", "reason", err)
			backoff = initialRetryDelay
			// A self-update drain paused the poller permanently and a
			// restart may have invalidated its inventory: rebuild either way.
			poller.stop()
			poller = nil
			continue
		}
		// A disconnected session starts the grace countdown; the next join
		// cancels it. A join failure never attached, so this is a no-op.
		poller.disconnected()
		if err != nil {
			slog.Error("agent disconnected", "error", err)
		}

		delay := reconnectDelay(healthy, isRefused(err), backoff)
		slog.Info("reconnecting", "delay", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		backoff = retryCeiling(backoff)
	}
}

// session owns one WebSocket connection: the reader and writer goroutines that
// serialize its I/O, the worker pools that execute jobs for it, and the queue
// their results come back on. Everything it owns is torn down by stop.
type session struct {
	ws              *wsConn
	topic           string
	hostname        string
	traps           <-chan *pb.SnmpTrap
	localScheduling bool

	// ctx is the session I/O context. It is detached from the agent context so
	// a process shutdown can keep writing spooled results while the session
	// drains; cancel — via stop — is what actually ends it. jobCtx tracks the
	// agent context: jobs and scheduled work die on shutdown while the spool
	// flushes around them.
	ctx    context.Context
	cancel context.CancelFunc
	jobCtx context.Context

	writeCh    chan writeRequest
	msgCh      chan channelMsg
	errCh      chan error
	writeErrCh chan error
	// abortCh carries errSelfUpdateAborted when a drained session must be
	// replaced because the re-exec it was drained for did not happen.
	abortCh    chan error
	readerDone chan struct{}
	writerDone chan struct{}

	// pools and results exist only once the channel join has been accepted.
	// With a process poller they are
	// borrowed for the session's lifetime and survive its end (C1/D2).
	pools     *jobPools
	scheduler *recurringScheduler
	results   *resultQueue
	notices   <-chan outbound
	// poller is the process-level poller this session transports, if any.
	poller *processPoller

	refCounter atomic.Uint64

	// joinRef is the ref used for the successful phx_join; Phoenix V2 push
	// frames repeat it as join_ref.
	joinRef string
	// v2 marks a Phoenix serializer V2 transport (binary frames), confirmed
	// by the join reply's shape. Legacy servers keep JSON frames.
	v2 bool
	// serverCapabilities holds the capability list the join reply confirmed.
	serverCapabilities map[string]struct{}
	// resultBatches enables result_batch/result_ack sends.
	resultBatches bool
	// inventoryUpdates enables inventory_update handling.
	inventoryUpdates bool

	// inventoryWork decodes multi-megabyte inventory frames off the session
	// loop (B8); the decoded result is applied from the loop in order.
	inventoryWork   chan inventoryDecodeRequest
	inventoryResult chan inventoryDecodeResult

	// pending tracks result refs awaiting a server phx_reply so a rejected
	// delivery (e.g. an oversized payload) can be retried instead of being
	// acked on websocket write alone. Only the session loop touches it.
	// pendingSeq numbers insertions; pendingOrder is a ring of refs so the
	// count cap evicts the oldest without scanning the map (B8).
	pending      map[string]pendingResult
	pendingOrder []string
	pendingHead  int
	pendingSeq   uint64

	// ackedResults counts spooled results the writer acknowledged. The
	// shutdown drain reads it from its own goroutine to log how many
	// results it flushed.
	ackedResults atomic.Uint64
}

// runSessionWithPoller runs one WebSocket session as a transport for the
// process poller. The poller's pools, scheduler and inventory survive the
// session's end; only the socket I/O and the inventory decoder are torn down.
func runSessionWithPoller(
	ctx context.Context,
	baseURL, token string,
	traps <-chan *pb.SnmpTrap,
	results *resultQueue,
	poller *processPoller,
) error {
	endpoint, err := url.JoinPath(baseURL, "socket/agent/websocket")
	if err != nil {
		return fmt.Errorf("build websocket endpoint: %w", err)
	}
	slog.Info("connecting", "url", sanitizeURL(endpoint))

	ws, err := wsDial(ctx, endpoint, token)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = ws.Close() }()

	// Include nanoseconds and a process-local sequence so immediate reconnects
	// cannot reuse a Phoenix topic, even when the clock has low resolution.
	agentID := newAgentID()

	slog.Info("connected", "agent_id", agentID)

	hostname, err := getHostname()
	if err != nil {
		slog.Error("resolve hostname", "error", err)
	}

	// The session context is detached from the agent context: on process
	// shutdown the loop must keep writing spooled results while it drains,
	// which a dead I/O context cannot do. Jobs, checks and scheduled work get
	// the poller's context — still bound to the agent context — so in-flight
	// work is cancelled on shutdown while the spool flushes around it.
	sessionCtx, sessionCancel := context.WithCancel(context.WithoutCancel(ctx))
	// wsDial requests Phoenix serializer V2. Framing is independent of
	// application capabilities: without them payloads remain base64 JSON in
	// text arrays; with them raw protobuf rides kind-zero binary frames.
	v2Framing := true
	s := &session{
		ws:              ws,
		topic:           "agent:" + agentID,
		hostname:        hostname,
		traps:           traps,
		v2:              v2Framing,
		localScheduling: poller.pools.localScheduling,
		ctx:             sessionCtx,
		cancel:          sessionCancel,
		writeCh:         make(chan writeRequest, 256),
		msgCh:           make(chan channelMsg, 100),
		errCh:           make(chan error, 1),
		writeErrCh:      make(chan error, 1),
		abortCh:         make(chan error, 1),
		readerDone:      make(chan struct{}),
		writerDone:      make(chan struct{}),
		results:         results,
		poller:          poller,
	}
	s.refCounter.Store(1)

	// The reader must run before the join so the reply can be received. Both
	// goroutines are joined by stop, which is registered before either can
	// fail.
	go s.read()
	go s.write()
	defer s.stop()

	if err := s.join(token); err != nil {
		return err
	}

	// A session joined: any pending self-update is proven. Clear the marker
	// and stop the rollback watchdog before work starts.
	updateJoined()

	// Attach the process poller only after the join was accepted: a revoked
	// token reconnects every few seconds and must not stop the poller or
	// replace the metrics pointer with a failing transport.
	s.pools = poller.pools
	s.scheduler = poller.scheduler
	s.notices = poller.pools.notices
	s.jobCtx = poller.workCtx
	poller.connected()

	// Async inventory decoding (B8): multi-megabyte frames no longer stop
	// result delivery while they decode.
	s.startInventoryDecoder()

	// C4: a held result whose ack never arrived is resent with its original
	// sequence after reconnect; the server's cumulative ack deduplicates the
	// accounting even if the storage layer sees the frame twice.
	s.results.requeueUnacked()

	// Let the self-update path flush the spool before it re-execs. The hook is
	// cleared on teardown so a stale session can never be drained.
	drain := s.drainResults
	drainResultSpool.Store(&drain)
	defer drainResultSpool.Store(nil)
	defer drainedSession.CompareAndSwap(s, nil)

	// Publish update-critical deployment metadata as soon as the join is
	// accepted. A full queue is non-fatal because the ticker will retry.
	if s.sendBinary("heartbeat", s.heartbeat()) {
		slog.Debug("sent heartbeat")
	}

	return s.loop(ctx)
}

// read pumps inbound messages until the connection fails.
func (s *session) read() {
	defer close(s.readerDone)
	for {
		kind, data, err := s.ws.ReadMessage(s.ctx)
		if err != nil {
			// fail() elsewhere (an abort, the writer) cancels the session;
			// once that cancellation is visible this read error is only its
			// echo. Posting it would shadow the real cause with "read:
			// context canceled" in sessionErr and the loop select.
			if s.ctx.Err() != nil {
				return
			}
			s.fail(s.errCh, err)
			return
		}
		msg, err := decodePhoenixMessage(kind, data)
		if err != nil {
			// A malformed Phoenix frame is a protocol failure, not a message
			// to ignore: the peer (or a proxy) is not speaking the negotiated
			// serializer, so reconnect and renegotiate.
			s.fail(s.errCh, fmt.Errorf("decode websocket frame: %w", err))
			return
		}
		msg.Binary = kind == websocket.MessageBinary
		select {
		case s.msgCh <- msg:
		case <-s.ctx.Done():
			return
		}
	}
}

// write serializes every outbound frame; the session loop is its only producer.
func (s *session) write() {
	defer close(s.writerDone)
	for request := range s.writeCh {
		var err error
		if request.binary {
			err = s.ws.WriteBinary(s.ctx, request.data)
		} else {
			err = s.ws.WriteText(s.ctx, request.data)
		}
		if request.ack != nil {
			request.ack <- err
		}
		// The frame bytes were fully consumed by WriteText — pooled buffers
		// return to the pool whether the write succeeded or not.
		if request.buf != nil {
			putFrameBuffer(request.buf)
		}
		if err != nil {
			// Same echo rule as the reader: once the session context is
			// cancelled by another failure, this write error is only the
			// echo and must not shadow the real cause (e.g. an abort) in
			// sessionErr or the loop select.
			// runAgentWithScheduling logs the error the session returns,
			// so the writer only publishes it.
			if s.ctx.Err() != nil {
				return
			}
			s.fail(s.writeErrCh, err)
			return
		}
	}
}

// fail publishes err - dropping it when an earlier error is already queued -
// and only then cancels the session. Publishing first is what lets a loop that
// wakes on the cancellation still report the real cause instead of racing the
// error channel.
func (s *session) fail(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
	s.cancel()
}

// stop tears the session down within one shared shutdown budget: socket I/O
// first, then the inventory worker and both I/O goroutines. A process-poller
// session stops only its transport; the poller keeps polling across
// disconnects (C1/D2) and is drained by its own stop.
func (s *session) stop() {
	s.cancel()
	_ = s.ws.Close()

	if s.inventoryWork != nil {
		close(s.inventoryWork)
	}

	close(s.writeCh)
	<-s.writerDone
	<-s.readerDone
}

// join performs the phx_join exchange, validates the reply and records the
// transport/capability negotiation. The join payload carries the agent's
// capability tokens because the initial inventory can arrive before the
// first heartbeat; the reply's `response.capabilities` is authoritative for
// what the server will send.
func (s *session) join(token string) error {
	joinPayload, _ := json.Marshal(struct {
		Token        string   `json:"token"`
		Capabilities []string `json:"capabilities"`
	}{Token: token, Capabilities: inventoryCapabilities()})
	joinRef := "1"
	s.joinRef = joinRef
	// json.Marshal'd payloads are always valid, so the V2 text encoder cannot
	// fail here; keep the buffer release unconditional.
	joinBuf, joinData, _ := encodePhoenixV2Text(
		s.topic, "phx_join", joinRef, &joinRef, joinPayload)
	defer putFrameBuffer(joinBuf)
	if err := s.ws.WriteText(s.ctx, joinData); err != nil {
		return fmt.Errorf("send join: %w", err)
	}
	slog.Debug("sent channel join request")

	timer := time.NewTimer(joinTimeout)
	defer timer.Stop()
	select {
	case msg := <-s.msgCh:
		capabilities, err := parseJoinReplyMsg(msg, s.topic)
		if err != nil {
			return err
		}
		s.serverCapabilities = make(map[string]struct{}, len(capabilities))
		for _, capability := range capabilities {
			s.serverCapabilities[capability] = struct{}{}
		}
		// Serializer V2 framing is already negotiated by the dial query. The
		// confirmed application capabilities only select raw protobuf lanes.
		s.resultBatches = s.hasCapability(capabilityResultBatch)
		s.inventoryUpdates = s.hasCapability(capabilityInventoryUpdate)
		slog.Info("channel joined",
			"serializer", map[bool]string{true: "v2", false: "v1"}[s.v2],
			"capabilities", len(capabilities))
		return nil
	case err := <-s.errCh:
		return fmt.Errorf("read during join: %w", err)
	case <-timer.C:
		return errors.New("join timeout")
	}
}

func (s *session) hasCapability(capability string) bool {
	_, ok := s.serverCapabilities[capability]
	return ok
}

// rawBinaryPayload reports whether this server confirmed the capability lanes
// that consume raw protobuf in Phoenix V2 binary frames. Without them, V2
// framing still carries the legacy base64 JSON payload in text arrays.
func (s *session) rawBinaryPayload() bool {
	return s.v2 && len(s.serverCapabilities) > 0
}

// marshalPhoenixEnvelope selects the exact wire representation: raw protobuf
// in a kind-zero binary client push for capability servers, base64 JSON in a
// V2 text array otherwise, and the legacy V1 object without V2 framing.
func marshalPhoenixEnvelope(
	topic, event, joinRef string,
	payload []byte,
	ref *string,
	v2, raw bool,
) (*bytes.Buffer, []byte, bool, error) {
	if raw {
		frameRef := ""
		if ref != nil {
			frameRef = *ref
		}
		buf, data, err := encodePhoenixV2Push(topic, event, joinRef, frameRef, payload)
		return buf, data, true, err
	}
	if v2 {
		buf, data, err := encodePhoenixV2Text(topic, event, joinRef, ref, payload)
		return buf, data, false, err
	}
	buf, data := marshalChannelFrame(topic, event, json.RawMessage(payload), ref)
	return buf, data, false, nil
}

// parseJoinReplyMsg validates an already kind-dispatched Phoenix frame. Both
// V2 arrays/binary replies and a legacy V1 object reply produce channelMsg.
func parseJoinReplyMsg(reply channelMsg, topic string) ([]string, error) {
	if reply.Event != "phx_reply" {
		return nil, fmt.Errorf("expected phx_reply, got %s", reply.Event)
	}
	status := reply.Status
	var payloadStatus struct {
		Status   string `json:"status"`
		Response struct {
			Reason       string   `json:"reason"`
			Capabilities []string `json:"capabilities"`
		} `json:"response"`
	}
	if status == "" {
		if err := json.Unmarshal(reply.Payload, &payloadStatus); err != nil {
			return nil, fmt.Errorf("join reply payload: %w", err)
		}
		status = payloadStatus.Status
	} else if err := json.Unmarshal(reply.Payload, &payloadStatus.Response); err != nil && len(reply.Payload) > 0 && string(reply.Payload) != "{}" {
		return nil, fmt.Errorf("join reply payload: %w", err)
	}
	if reply.Topic != topic {
		return nil, fmt.Errorf("join reply for topic %q, want %q", reply.Topic, topic)
	}
	if reply.Ref == nil || *reply.Ref != "1" {
		return nil, fmt.Errorf("join reply has unexpected ref")
	}
	if status != "ok" {
		if payloadStatus.Response.Reason != "" {
			return nil, refusedError{fmt.Errorf("join rejected: %s (%s)", status, payloadStatus.Response.Reason)}
		}
		return nil, refusedError{fmt.Errorf("join rejected: %s", status)}
	}
	return payloadStatus.Response.Capabilities, nil
}

func (s *session) nextRef() string {
	return strconv.FormatUint(s.refCounter.Add(1), 10)
}

// framePool recycles the buffers channel frames are built in: every spooled
// result and heartbeat takes this path, so pooling removes the per-message
// marshal copies that otherwise dominate allocation under result floods.
var framePool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// maxPooledFrameBuffer caps the buffers returned to framePool. A base64
// config backup can grow a frame to several MiB; pooling it would pin that
// memory and hand it to the next heartbeat, so oversized buffers are left
// for the garbage collector instead.
const maxPooledFrameBuffer = 64 << 10

func putFrameBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledFrameBuffer {
		return
	}
	buf.Reset()
	framePool.Put(buf)
}

// appendBinaryPayload writes the `{"binary":"<base64>"}` payload envelope,
// marshalling the protobuf once and streaming the base64 directly into buf.
// bytes.Buffer writes cannot fail, so the encoder's results are discarded.
func appendBinaryPayload(buf *bytes.Buffer, msg proto.Message) error {
	buf.WriteString(`{"binary":"`)
	bin, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	_, _ = enc.Write(bin)
	_ = enc.Close()
	buf.WriteString(`"}`)
	return nil
}

// marshalChannelFrame assembles the fixed-shape Phoenix channel envelope
// directly into a pooled buffer instead of running a struct marshal. Topic
// and event are internal ASCII identifiers, so strconv quoting is safe; the
// ref is written as a JSON string when present. Callers must release the
// buffer (via the writeRequest buf field or putFrameBuffer) before
// reusing or discarding the data slice.
func marshalChannelFrame(topic, event string, payload json.RawMessage, ref *string) (*bytes.Buffer, []byte) {
	buf := framePool.Get().(*bytes.Buffer)
	buf.WriteString(`{"topic":`)
	buf.WriteString(strconv.Quote(topic))
	buf.WriteString(`,"event":`)
	buf.WriteString(strconv.Quote(event))
	buf.WriteString(`,"payload":`)
	buf.Write(payload)
	if ref != nil {
		buf.WriteString(`,"ref":`)
		buf.WriteString(strconv.Quote(*ref))
	} else {
		buf.WriteString(`,"ref":null`)
	}
	buf.WriteByte('}')
	return buf, buf.Bytes()
}

// sendBinary queues a protobuf message. Capability servers receive the exact
// protobuf bytes in a V2 binary client push; V2 framing without capabilities
// receives the legacy base64 JSON object in a text array.
func (s *session) sendBinary(event string, msg proto.Message) bool {
	raw := s.rawBinaryPayload()
	payload := framePool.Get().(*bytes.Buffer)
	if raw {
		bin, err := proto.Marshal(msg)
		if err != nil {
			putFrameBuffer(payload)
			slog.Error("marshal protobuf", "error", err)
			return false
		}
		payload.Write(bin)
	} else if err := appendBinaryPayload(payload, msg); err != nil {
		putFrameBuffer(payload)
		slog.Error("marshal protobuf", "error", err)
		return false
	}
	buf, data, binaryFrame, err := marshalPhoenixEnvelope(
		s.topic, event, s.joinRef, payload.Bytes(), nil, s.v2, raw)
	putFrameBuffer(payload)
	if err != nil {
		slog.Error("marshal channel frame", "error", err)
		return false
	}
	if !enqueueWrite(s.ctx, s.writeCh, writeRequest{
		data:   data,
		buf:    buf,
		binary: binaryFrame,
	}, event) {
		putFrameBuffer(buf)
		return false
	}
	return true
}

// queueResultWrite hands a result frame to the websocket writer and returns
// its in-flight handle instead of blocking on the write. The session loop
// resolves the handle from its select, so inbound messages and heartbeats
// keep being serviced while a large frame is on the wire. When enqueueing
// fails the frame is dropped and the caller still owns the spooled slot.
//
// The message carries a ref so the server's phx_reply can be correlated back
// to this result: a rejected delivery (oversized payload, decode failure) is
// retried once by handleResultReply instead of being silently dropped.
func (s *session) queueResultWrite(result outbound, spooled bool) (*inFlightWrite, error) {
	return s.queueResultFrame([]outbound{result}, result.event, spooled)
}

// queueResultFrame sends one frame containing results. With result_batch_v1
// negotiated the frame is a single "result_batch" envelope; without it the
// results must arrive one per frame and only the first is sent.
func (s *session) queueResultFrame(results []outbound, event string, spooled bool) (*inFlightWrite, error) {
	if s.ctx.Err() != nil {
		return nil, s.sessionErr()
	}
	if len(results) == 0 {
		return nil, errors.New("queue result frame without results")
	}
	// Capability servers always receive the raw result_batch protobuf lane,
	// including a singleton; this keeps one payload representation per lane
	// and lets the cumulative ack release every spooled sequence.
	batched := spooled && s.resultBatches
	frameEvent := event
	if !batched {
		results = results[:1]
	}

	// Assign delivery sequences in send order and hold them until the
	// server's cumulative ack. A requeued frame arrives with sequence 0 and
	// is renumbered here (issue 5148).
	//
	// This must run before the batch is encoded: each envelope carries its
	// sequence, so encoding first put an unassigned result on the wire as
	// sequence 0 while the in-memory copy was numbered afterwards. The server
	// refuses a batch whose first sequence is not above the position it has
	// already handled, so every fresh batch was rejected as a duplicate (and
	// the ack that would have released it never arrived).
	if spooled && s.results.byteBounded() {
		for i := range results {
			if results[i].sequence == 0 {
				results[i].sequence = s.results.nextSeq.Add(1)
			}
			s.results.hold(results[i])
		}
	}

	var msg proto.Message
	if batched {
		frameEvent = "result_batch"
		msg = resultBatchEncoder(results)
	}

	ref := s.nextRef()
	var payload []byte
	if batched {
		// Capability lanes over V2 carry raw protobuf bytes: no base64, no
		// JSON pass over a multi-megabyte batch (D5, B7). proto.Marshal is
		// the one allocation; the envelope bytes go straight to the frame
		// builder, which performs the only remaining copy into the wire
		// buffer.
		bin, err := proto.Marshal(msg)
		if err != nil {
			s.unholdSpooled(results)
			return nil, fmt.Errorf("encode %s frame: %w", frameEvent, err)
		}
		payload = bin
	} else {
		result := results[0]
		if len(result.protoPayload) > 0 {
			// Capability-less V2 and V1 servers consume the legacy base64
			// JSON object. This wrapper is intentionally only built on send.
			payload = base64BinaryPayload(result.protoPayload)
		} else {
			payload = result.payload
		}
	}
	buf, data, binaryFrame, envErr := marshalPhoenixEnvelope(
		s.topic, frameEvent, s.joinRef, payload, &ref, s.v2, batched)
	if envErr != nil {
		s.unholdSpooled(results)
		putFrameBuffer(buf)
		return nil, fmt.Errorf("encode %s frame: %w", frameEvent, envErr)
	}
	ack := make(chan error, 1)
	if !enqueueWrite(s.ctx, s.writeCh, writeRequest{
		data:   data,
		ack:    ack,
		buf:    buf,
		binary: binaryFrame,
	}, frameEvent) {
		putFrameBuffer(buf)
		s.trackPendingCleanup(ref, results)
		s.unholdSpooled(results)
		if s.ctx.Err() != nil {
			return nil, s.sessionErr()
		}
		return nil, fmt.Errorf("queue %s result for websocket write: timeout", frameEvent)
	}
	s.trackPendingFrame(ref, results)
	return &inFlightWrite{
		result:  results[0],
		results: results,
		event:   frameEvent,
		ack:     ack,
		ref:     ref,
		binary:  binaryFrame,
		spooled: spooled,
	}, nil
}

// unholdSpooled removes held sequences before a retry re-enters the spool, so
// capacity is not double-charged while the payload is retained.
func (s *session) unholdSpooled(results []outbound) {
	if !s.results.byteBounded() {
		return
	}
	for _, result := range results {
		s.results.unhold(result.sequence)
	}
}

// trackPendingFrame records a sent frame for rejection correlation.
func (s *session) trackPendingFrame(ref string, results []outbound) {
	if s.pending == nil {
		s.pending = make(map[string]pendingResult)
	}
	s.pendingSeq++
	entry := pendingResult{
		result:  results[0],
		results: results,
		seq:     s.pendingSeq,
	}
	s.pushPendingOrder(ref)
	s.pending[ref] = entry
}

func (s *session) trackPendingCleanup(ref string, results []outbound) {
	// The frame never reached the writer; nothing waits on its ref.
	delete(s.pending, ref)
	s.removePendingOrder(ref)
	_ = results
}

// pushPendingOrder appends a ref to the eviction ring, growing it once.
func (s *session) pushPendingOrder(ref string) {
	if len(s.pendingOrder) < maxPendingResults {
		s.pendingOrder = append(s.pendingOrder, ref)
		return
	}
	if len(s.pending) >= maxPendingResults {
		s.evictOldestPending()
	}
	s.pendingOrder[s.pendingHead] = ref
	s.pendingHead = (s.pendingHead + 1) % len(s.pendingOrder)
}

// removePendingOrder drops a ref from the eviction ring after a failed queue.
func (s *session) removePendingOrder(ref string) {
	for i := range s.pendingOrder {
		pos := (s.pendingHead + i) % len(s.pendingOrder)
		if s.pendingOrder[pos] == ref {
			s.pendingOrder[pos] = ""
			return
		}
	}
}

// resolveInFlight settles a completed write. Count mode frees the spool slot
// on writer success (legacy at-most-once). Byte mode with result_ack_v1 keeps
// the result held until the server's cumulative storage sequence arrives
// (C4); without the capability negotiation it falls back to write success.
// Only the session loop pushes to the retry lane.
func (s *session) resolveInFlight(w *inFlightWrite, err error) error {
	results := inFlightResults(w)
	if err != nil {
		s.trackPendingCleanup(w.ref, results)
		if w.spooled {
			s.retryResults(results)
		}
		return fmt.Errorf("write %s result: %w", w.event, err)
	}
	if pending, ok := s.pending[w.ref]; ok {
		pending.sentAt = time.Now()
		s.pending[w.ref] = pending
	}
	if w.spooled {
		s.ackedResults.Add(uint64(len(results)))
		if s.results.byteBounded() && s.hasCapability(capabilityResultAck) {
			// Held until result_ack; the ring releases the capacity.
			slog.Debug("awaiting result ack", "event", w.event, "count", len(results))
		} else {
			for _, result := range results {
				s.results.ack(result)
			}
		}
		slog.Debug("sent result", "event", w.event, "count", len(results))
	} else {
		slog.Debug("sent overload notice", "event", w.event)
	}
	if w.reply != nil {
		s.handleResultReply(*w.reply)
	}
	return nil
}

// retryResults puts a failed frame's results back at the head of the spool.
func (s *session) retryResults(results []outbound) {
	if len(results) == 0 {
		return
	}
	if s.results.byteBounded() {
		s.unholdSpooled(results)
		s.results.retryBatch(results)
		return
	}
	s.results.retry(results[0])
}

func inFlightResults(w *inFlightWrite) []outbound {
	if w == nil {
		return nil
	}
	if len(w.results) > 0 {
		return w.results
	}
	return []outbound{w.result}
}

// settleInFlight resolves a still-pending write when the loop is ending for
// another reason. A write that already completed is honored (slot released);
// one still in flight is requeued for the next session — the same
// at-most-once semantics as before, since a write that lands after
// cancellation can surface as a duplicate.
func (s *session) settleInFlight(w *inFlightWrite) {
	if w == nil {
		return
	}
	select {
	case err := <-w.ack:
		_ = s.resolveInFlight(w, err)
	default:
		if w.spooled {
			s.retryResults(inFlightResults(w))
		}
	}
}

// evictOldestPending deletes the entry with the lowest insertion sequence via
// the pending-order ring.
func (s *session) evictOldestPending() {
	var oldestRef string
	var oldestSeq uint64
	for ref, p := range s.pending {
		if oldestRef == "" || p.seq < oldestSeq {
			oldestRef, oldestSeq = ref, p.seq
		}
	}
	if oldestRef == "" {
		return
	}
	delete(s.pending, oldestRef)
	s.removePendingOrder(oldestRef)
}

// prunePending drops entries the server never answered. It runs on the
// channel heartbeat tick so the map cannot grow unboundedly between replies
// even when no new results are being sent.
func (s *session) prunePending() {
	cutoff := time.Now().Add(-pendingReplyTTL)
	for ref, p := range s.pending {
		if !p.sentAt.IsZero() && p.sentAt.Before(cutoff) {
			delete(s.pending, ref)
		}
	}
}

// drainResults prepares the session for a self-update re-exec: the recurring
// scheduler and the worker pools are paused, so no new tick or submission
// starts, while work already admitted keeps its live context and finishes.
// That covers running recurring ticks and one-shot jobs that are queued,
// running, or still in jitter or a gate wait. A recurring tick still in its
// own jitter or gate wait has not been admitted; the paused pool refuses it.
// The spool is then flushed until every slot is free (the semaphores hold a
// token per in-use slot), meaning every enqueued or in-flight result was
// written to the websocket and acked. The session loop keeps delivering
// results concurrently; drain only gates acceptance. Returns false when the
// caller's bounded context expires first.
//
// The drain cannot be undone in place, since the pause has no resume, so the
// session is recorded in drainedSession and ended by abortDrainedSession if
// the re-exec does not happen.
func (s *session) drainResults(ctx context.Context) bool {
	drainedSession.Store(s)
	return s.drainSpool(ctx)
}

// drainSpool refuses new work and waits out every queued result. The caller
// supplies a bounded context; the session loop must still be running, since
// it is what delivers results during the wait. Self-update calls it through
// drainResults, which also records the session for abortDrainedSession; the
// shutdown drain calls it directly because the process is leaving anyway.
func (s *session) drainSpool(ctx context.Context) bool {
	if s.pools != nil {
		s.pools.stopAccepting.Store(true)
		s.pools.pause()
	}
	if s.scheduler != nil {
		s.scheduler.pause()
	}

	// Pools are checked before the spool: a job sends its result before its
	// task returns, so once every pool is idle its result is already queued
	// and the spool check below covers it.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !s.resultsDrained() {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
	return true
}

// resultsDrained reports whether in-flight work has all finished and every
// queued result was written to the socket and acked. Pools are checked before
// the spool: a job sends its result before its task returns, so once every
// pool is idle its result is already queued. Shared by the self-update drain
// and the shutdown drain, which differ only in who waits for it (issue 2757).
func (s *session) resultsDrained() bool {
	poolsIdle := s.pools == nil || s.pools.idle()
	return poolsIdle && s.results.empty()
}

// drainForShutdown runs the spool drain behind a bounded budget on the
// process-shutdown path (issue 2757): SIGTERM with a non-empty spool used
// to exit with every queued result still in memory, a hole in each
// device's history exactly when the operator was watching for the change
// they just made. It calls drainSpool directly — not drainResults — so the
// process exit never records the session in drainedSession: that marker is
// reserved for the self-update drain, whose session abortDrainedSession
// ends if the re-exec does not happen. It closes `done` whether the flush
// finished or the budget expired so the session loop exits either way. The
// count of results still queued when the budget ran out is logged once, so
// a restart that lost data says so. "flushed" counts the writer acks during
// the drain, so it includes results queued after the drain started.
func (s *session) drainForShutdown(done chan<- struct{}) {
	defer close(done)

	if s.results == nil {
		return
	}

	ackedBefore := s.ackedResults.Load()
	ctx, cancel := context.WithTimeout(context.Background(), poolShutdownTimeout)
	defer cancel()

	if s.drainSpool(ctx) {
		slog.Info("shutdown drain flushed queued results", "flushed", s.ackedResults.Load()-ackedBefore)
		return
	}

	lost := len(s.results.items) + s.results.pendingAckCount()
	if lost > 0 {
		slog.Warn("shutdown drain timed out, results lost",
			"lost", lost,
			"flushed", s.ackedResults.Load()-ackedBefore,
			"timeout", poolShutdownTimeout)
	}
}

// abortDrainedSession ends the session a self-update drain stopped, if any.
// It runs whenever the update returns: a successful exec never does, so a
// return means the process — and the drained, job-refusing session — lives
// on. The reconnect that follows builds a fresh scheduler and pools.
func abortDrainedSession() {
	s := drainedSession.Swap(nil)
	if s == nil {
		return
	}
	// A cancelled jobCtx means the process is shutting down (or the session
	// already stopped). The loop is running the shutdown drain through the
	// session I/O context; failing the session would cancel that context and
	// abandon the flush. The shutdown drain ends the session itself.
	if s.jobCtx != nil && s.jobCtx.Err() != nil {
		slog.Info("self-update stood down during shutdown; the shutdown drain ends the session")
		return
	}
	slog.Warn("self-update did not re-exec after draining; reconnecting to restore job intake")
	s.fail(s.abortCh, errSelfUpdateAborted)
}

// handleResultReply consumes a phx_reply addressed to this channel. A reply
// with an error status means the server rejected the result (or a whole
// result_batch frame). Deterministic rejections (oversized payload) are
// dropped immediately — re-sending the identical marshalled bytes can only
// be rejected again — while transient rejections are retried once, then
// dropped loudly. The previous behaviour logged the rejection at debug while
// the spool slot had already been acked, so oversized results vanished with
// a false success.
func (s *session) handleResultReply(msg channelMsg) {
	if msg.Ref == nil {
		return
	}
	p, ok := s.pending[*msg.Ref]
	if !ok {
		return
	}
	delete(s.pending, *msg.Ref)
	s.removePendingOrder(*msg.Ref)
	results := p.results
	if len(results) == 0 {
		results = []outbound{p.result}
	}

	var reply struct {
		Status   string `json:"status"`
		Response struct {
			Reason string `json:"reason"`
		} `json:"response"`
	}
	if err := json.Unmarshal(msg.Payload, &reply); err != nil {
		slog.Warn("unparseable channel reply", "ref", *msg.Ref, "error", err)
		return
	}
	if reply.Status == "ok" {
		return
	}

	reason := reply.Response.Reason
	if reason == "" {
		reason = reply.Status
	}
	// Both rejections are deterministic: "Message too large" is a size check
	// and "Invalid message" a decode failure, so the identical bytes fail
	// again on every retry.
	if strings.HasPrefix(reason, "Message too large") || strings.HasPrefix(reason, "Invalid message") {
		slog.Error("server rejected result as undeliverable, dropping",
			"event", p.result.event, "reason", reason, "count", len(results))
		for _, result := range results {
			s.results.dropSent(result.sequence)
		}
		return
	}
	if p.result.attempts == 0 {
		for i := range results {
			results[i].attempts = p.result.attempts + 1
		}
		if reason == "overloaded" {
			slog.Warn("server overloaded, retrying result after a delay",
				"event", p.result.event, "delay", overloadRetryDelay,
				"count", len(results))
			s.requeueRejected(results, overloadRetryDelay)
			return
		}
		slog.Warn("server rejected result, retrying once",
			"event", p.result.event, "reason", reason, "count", len(results))
		s.requeueRejected(results, 0)
		return
	}
	slog.Error("server rejected result twice, dropping",
		"event", p.result.event, "reason", reason, "count", len(results))
	for _, result := range results {
		s.results.dropSent(result.sequence)
	}
}

// requeueRejected returns server-rejected results to the spool. The held
// ring entry is removed first so the requeue does not double-charge the byte
// budget, and the queue clears their delivery sequences so they renumber in
// send order (issue 5148).
func (s *session) requeueRejected(results []outbound, delay time.Duration) {
	if s.results.byteBounded() {
		s.unholdSpooled(results)
	}
	if delay > 0 {
		for _, result := range results {
			s.results.enqueueAfter(result, delay)
		}
		return
	}
	if s.results.byteBounded() && len(results) > 1 {
		if !s.results.enqueueBatch(results) {
			slog.Error("result retry dropped, spool full",
				"event", results[0].event, "count", len(results))
		}
		return
	}
	for _, result := range results {
		if !s.results.enqueue(result) {
			slog.Error("result retry dropped, spool full", "event", result.event)
		}
	}
}

// sessionErr reports why the session context was cancelled. Both I/O
// goroutines publish their error before cancelling, so a non-blocking drain
// returns the real cause rather than whichever select case happened to win.
// The abort and write channels are checked before errCh: a self-update
// abort cancels the session, the reader then sees only the cancellation
// echo, and the abort reason must not be lost to "read: context canceled".
func (s *session) sessionErr() error {
	select {
	case err := <-s.abortCh:
		return err
	default:
	}
	select {
	case err := <-s.writeErrCh:
		return fmt.Errorf("write: %w", err)
	default:
	}
	select {
	case err := <-s.errCh:
		return fmt.Errorf("read: %w", err)
	default:
	}
	return errSessionCancelled
}

func (s *session) heartbeat() *pb.AgentHeartbeat {
	localScheduling := s.localScheduling
	if s.pools != nil {
		localScheduling = s.pools.localScheduling
	}
	localIPs, subnets := localVantagePoint()
	hb := &pb.AgentHeartbeat{
		Version:              version,
		UptimeSeconds:        uint64(time.Since(processStart).Seconds()),
		Arch:                 runtime.GOARCH,
		Hostname:             s.hostname,
		IpAddress:            s.ws.LocalIP(),
		Container:            runningInContainer(),
		SchedulesJobs:        localScheduling,
		LocalIps:             localIPs,
		InterfaceSubnets:     subnets,
		ReportsVantagePoint:  true,
		SupportsConfigBackup: true,
		// The server dispatches plan-driven backups only to agents that
		// advertise this feature; MikroTik backups need no plan.
		ConfigBackupFeatures: []string{"plan_v1"},
		// Trap listener telemetry (issue 2754): the heartbeat is the only
		// channel the listener's health can reach the server through.
		TrapsEnabled:      trapsReportingEnabled.Load(),
		TrapListenerState: trapListenerStateString(),
		TrapsDropped:      trapDroppedTotal.Load(),
		// Protocol capabilities mirror the join payload: the server can use
		// the heartbeat alone for later protocol turns (result acks), while
		// the join payload covers the initial inventory.
		Capabilities: inventoryCapabilities(),
	}

	// Load telemetry (C6): one consistent snapshot of the process counters,
	// the active spool and every worker pool.
	metrics := heartbeatMetrics(s.results)
	hb.ResultsDropped = metrics.ResultDropped
	hb.SpoolDepth = metrics.SpoolDepth
	hb.SpoolBytes = metrics.SpoolBytes
	hb.SpoolLimitBytes = metrics.SpoolLimit
	hb.ScheduleLagMsP95 = metrics.ScheduleLagMS
	hb.SnmpTimeouts = metrics.SNMPTimeouts
	hb.RateLimitWaitMs = metrics.RateLimitWaitMS
	hb.SkippedTicks = metrics.SkippedTicks
	hb.InventoryCapacityDevices = uint32(metrics.InventoryCapacity)
	for _, load := range metrics.Pools {
		hb.Pools = append(hb.Pools, &pb.PoolLoad{
			Name:   load.Name,
			Busy:   uint32(load.Busy),
			Queued: uint32(load.Queued),
		})
	}

	// Inventory reconciliation (issue #2755): the newest pushed inventory
	// revision the agent applied and the last frame it refused. The server
	// re-pushes when applied_revision trails what it sent.
	if s.pools != nil {
		hb.AppliedRevision = s.pools.appliedRevision.Load()
		if rejected, ok := s.pools.rejectedInventory.Load().(string); ok {
			hb.InventoryRejected = rejected
		}
	}
	// The outcome of the last self-update attempt rides every heartbeat so
	// the fleet page shows what an update did, not just what it was told.
	if res := readUpdateResult(); res != nil {
		hb.UpdateTargetVersion = res.TargetVersion
		hb.UpdateError = res.Error
		hb.UpdateAttemptedAt = res.AttemptedAt
	}
	return hb
}

// localVantagePoint enumerates the host's non-loopback interface addresses so
// the server knows which subnets this agent is on-link for. Loopback,
// link-local and multicast addresses are excluded: they cannot carry a sweep.
// The lists are sorted so identical reports compare equal server-side.
func localVantagePoint() (localIPs, subnets []string) {
	ifaces, err := netInterfaces()
	if err != nil {
		slog.Warn("interface enumeration failed", "error", err)
		return nil, nil
	}
	seenSubnet := map[string]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := interfaceAddrs(&iface)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsLinkLocalMulticast() {
				continue
			}
			localIPs = append(localIPs, ipNet.IP.String())
			network := (&net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask}).String()
			if !seenSubnet[network] {
				seenSubnet[network] = true
				subnets = append(subnets, network)
			}
		}
	}
	slices.Sort(localIPs)
	slices.Sort(subnets)
	return localIPs, subnets
}

// loop is the session event loop. ctx is the agent-wide context; the session's
// own context signals connection failure.
//
// Result delivery is lane-aware (C3) and, with result_batch_v1, batched
// (D5): outage signals leave first, small measurements share one frame every
// 250 ms or 256 KB, and byte-bounded results stay held until the server's
// cumulative storage ack (C4).
//
// When ctx is cancelled the loop switches to draining instead of returning:
// drainResults — the same wait the self-update path uses — runs against the
// spool while the loop keeps delivering its contents, so a restart flushes
// queued results within poolShutdownTimeout instead of dropping them.
func (s *session) loop(ctx context.Context) error {
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	channelHeartbeatTicker := time.NewTicker(channelHeartbeatInterval)
	defer channelHeartbeatTicker.Stop()
	var batchTicker *time.Ticker
	var batchFlush <-chan time.Time
	if s.resultBatches {
		batchTicker = time.NewTicker(resultBatchFlushDelay)
		defer batchTicker.Stop()
		batchFlush = batchTicker.C
	}

	// inFlight is the one result frame the writer owns but has not yet
	// acknowledged. Keeping the cap at one preserves wire order — retries
	// always go out before newer spooled results — while the loop stays
	// responsive to inbound messages, traps and heartbeats during the write.
	var inFlight *inFlightWrite

	// lanes hold results already taken from the spool, grouped by delivery
	// priority, until they form the next frame.
	var lanes [5][]outbound
	flushDue := false

	// Shutdown asks for the same drain the self-update path gets (issue
	// 2757): the goroutine waits for pools to idle and the spool to empty
	// while this loop keeps delivering results, then exits the session with
	// nothing queued instead of abandoning up to 512 finished results.
	// `ctxDone` is set to nil after the first signal so a busy select does
	// not re-enter while the flush is in progress.
	ctxDone := ctx.Done()
	var drainDone chan struct{}

	// msgCh is gated off while an inventory frame waits on a full decode
	// queue, so a back-to-back full sync applies reader backpressure instead
	// of dropping chunks (issue 5149). parkedWork is nil until a frame
	// parks, which disables its send case.
	msgCh := s.msgCh
	var parkedReq inventoryDecodeRequest
	var parkedWork chan inventoryDecodeRequest

	for {
		if inFlight == nil {
			s.stageResults(&lanes)
			frame, event := s.nextResultFrame(&lanes, flushDue)
			flushDue = false
			if len(frame) > 0 {
				w, err := s.queueResultFrame(frame, event, true)
				if err != nil {
					s.retryResults(frame)
					s.results.requeueLanes(&lanes)
					return err
				}
				inFlight = w
			}
		}

		// Only one result write may be in flight, so the result and notice
		// sources drop out of the select while a write is outstanding.
		var resultsCh <-chan outbound
		var noticesCh <-chan outbound
		var ackCh <-chan error
		trapCh := (<-chan *pb.SnmpTrap)(nil)
		if inFlight == nil {
			resultsCh = s.results.items
			noticesCh = s.notices
			// Trap backpressure (C5): stop reading the trap channel while
			// the trap sub-budget has no room left, rather than dropping
			// each one as a generic result overflow (issue 5165).
			if s.results.hasTrapRoomFor(1) {
				trapCh = s.traps
			}
		} else {
			ackCh = inFlight.ack
		}

		select {
		case <-ctxDone:
			slog.Info("shutdown signal, draining queued results before exit")
			// An in-flight self-update must not re-exec while the process is
			// shutting down: stand it down now, and after the drain give it
			// a bounded window to finish the restore its cancellation
			// triggers before the process exits.
			cancelActiveUpdate()
			ctxDone = nil
			drainDone = make(chan struct{})
			go s.drainForShutdown(drainDone)
			continue

		case <-drainDone:
			waitActiveUpdate(shutdownUpdateWait)
			return s.endLoop(&lanes, inFlight, nil)
		case <-s.ctx.Done():
			return s.endLoop(&lanes, inFlight, s.sessionErr())

		case err := <-s.errCh:
			return s.endLoop(&lanes, inFlight, fmt.Errorf("read: %w", err))

		case err := <-s.writeErrCh:
			// The writer publishes its ack before writeErrCh, so a pending
			// in-flight write is already resolved on its channel.
			return s.endLoop(&lanes, inFlight, fmt.Errorf("write: %w", err))

		case err := <-s.abortCh:
			return s.endLoop(&lanes, inFlight, err)

		case err := <-ackCh:
			w := inFlight
			inFlight = nil
			if err := s.resolveInFlight(w, err); err != nil {
				return s.endLoop(&lanes, nil, err)
			}

		case result := <-resultsCh:
			lanes[result.lane] = append(lanes[result.lane], result)

		case notice := <-noticesCh:
			w, err := s.queueResultWrite(notice, false)
			if err != nil {
				return s.endLoop(&lanes, nil, err)
			}
			inFlight = w

		case trap, ok := <-trapCh:
			if !ok {
				slog.Warn("snmp trap listener stopped")
				s.traps = nil
				continue
			}
			if trap == nil {
				slog.Warn("ignoring nil snmp trap")
				continue
			}
			// Traps are process-scoped input, not session-scoped work. Spool
			// them so a failed write is retried by the next connection. The
			// enqueue verdict for THIS trap is the drop signal: a shared
			// spool counter would also count poll results another
			// goroutine dropped between load and check (C5). A marshal
			// failure is not spool pressure and counts separately (issue
			// 5165).
			encoded, ok := encodeOutbound("trap", trap, "")
			if !ok {
				countTrapEncodeDrop()
				continue
			}
			if s.results.enqueue(encoded) {
				slog.Debug("spooled snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid)
			} else {
				countTrapSpoolDrop()
			}

		case msg := <-msgCh:
			if msg.Event == "phx_reply" && (msg.Topic == s.topic || msg.Topic == "phoenix") {
				if inFlight != nil && msg.Ref != nil && *msg.Ref == inFlight.ref {
					inFlight.reply = &msg
				} else {
					s.handleResultReply(msg)
				}
				continue
			}
			if msg.Event == "result_ack" {
				if sequence, ok := decodeResultAck(msg); ok {
					if released := s.results.ackThrough(sequence); released > 0 {
						slog.Debug("server acknowledged results", "through", released)
					}
				}
				continue
			}
			if s.isInventoryEvent(msg.Event) {
				if s.inventoryWork == nil {
					// Compatibility path: no decoder (a directly
					// constructed session). Inventory events never end the
					// loop; discard the handleMessage pair it returns.
					_, _ = handleMessage(s.jobCtx, msg, s.topic, s.pools, s.results)
					continue
				}
				request := inventoryDecodeRequest{
					event:    msg.Event,
					payload:  msg.Payload,
					rawProto: msg.Binary && s.inventoryUpdates,
				}
				select {
				case s.inventoryWork <- request:
				default:
					// Park instead of refusing: the server pushes a full
					// sync's chunks back to back faster than the shallow
					// decode queue can drain, and one refused chunk voids
					// the whole atomic assembly. Stop reading msgCh until
					// the decoder takes this frame; heartbeats, acks and
					// decoded results keep flowing meanwhile.
					parkedReq = request
					parkedWork = s.inventoryWork
					msgCh = nil
				}
				continue
			}
			shouldEnd, endErr := handleMessage(s.jobCtx, msg, s.topic, s.pools, s.results)
			if shouldEnd {
				return s.endLoop(&lanes, inFlight, endErr)
			}

		case parkedWork <- parkedReq:
			parkedWork = nil
			msgCh = s.msgCh

		case decoded := <-s.inventoryResult:
			s.applyInventoryDecode(decoded, s.pools, s.results)

		case <-heartbeatTicker.C:
			hb := s.heartbeat()
			if s.sendBinary("heartbeat", hb) {
				slog.Debug("sent heartbeat")
			}

		case <-channelHeartbeatTicker.C:
			// Sweep expired pending results on the same tick: the server only
			// replies on rejection, so TTL — not ack — bounds the map.
			s.prunePending()
			ref := s.nextRef()
			payload := []byte(`{}`)
			// Topic, ref and the {} payload are constants that cannot fail
			// the envelope marshal; no error return is needed here.
			buf, data, binaryFrame, _ := marshalPhoenixEnvelope(
				"phoenix", "heartbeat", s.joinRef, payload, &ref, s.v2, false)
			if enqueueWrite(s.ctx, s.writeCh, writeRequest{
				data:   data,
				buf:    buf,
				binary: binaryFrame,
			}, "heartbeat") {
				slog.Debug("sent channel heartbeat", "ref", ref)
			} else {
				putFrameBuffer(buf)
			}

		case <-batchFlush:
			// The 250 ms window closed: the next loop pass flushes whatever
			// the lanes hold.
			flushDue = true
			if inFlight == nil {
				s.stageResults(&lanes)
				frame, event := s.nextResultFrame(&lanes, true)
				if len(frame) > 0 {
					w, err := s.queueResultFrame(frame, event, true)
					if err != nil {
						s.retryResults(frame)
						s.results.requeueLanes(&lanes)
						return err
					}
					inFlight = w
				}
				flushDue = false
			}
		}
	}
}

// endLoop settles the in-flight write and returns staged-but-unsent lane
// results to the spool before the session returns. The next session (or
// poller) replays them.
func (s *session) endLoop(lanes *[5][]outbound, inFlight *inFlightWrite, err error) error {
	s.settleInFlight(inFlight)
	s.results.requeueLanes(lanes)
	return err
}

// enqueueWrite gives the session writer a bounded opportunity to accept a
// message. A full queue drops only that message; the writer's I/O timeout is
// responsible for detecting a wedged connection.
func enqueueWrite(
	ctx context.Context,
	writeCh chan<- writeRequest,
	request writeRequest,
	event string,
) bool {
	select {
	case writeCh <- request:
		return true
	case <-ctx.Done():
		return false
	default:
	}

	timer := time.NewTimer(writeQueueTimeout)
	defer timer.Stop()

	select {
	case writeCh <- request:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		slog.Error("write channel full, dropping message", "event", event)
		return false
	}
}

func newAgentID() string {
	return fmt.Sprintf("agent-%d-%d", time.Now().UnixNano(), agentIDCounter.Add(1))
}

// handleMessage dispatches incoming channel messages.
// Returns whether the session should end and the reason for reconnecting.
func handleMessage(
	ctx context.Context,
	msg channelMsg,
	topic string,
	pools *jobPools,
	out *resultQueue,
) (bool, error) {
	// Ignore messages not addressed to our topic (except Phoenix control messages)
	if msg.Topic != topic && msg.Topic != "phoenix" {
		slog.Debug("ignoring message for different topic", "got", msg.Topic, "want", topic)
		return false, nil
	}

	// phx_reply never reaches here: the session loop routes every reply on
	// this topic or "phoenix" to handleResultReply.
	switch msg.Event {
	case "phx_error", "phx_close":
		slog.Warn("phoenix channel ended, reconnecting",
			"event", msg.Event,
			"topic", msg.Topic)
		return true, errChannelReloaded

	case "jobs":
		if pools.stopAccepting.Load() {
			refuseInventory(ctx, pools, out, msg.Event)
			return false, nil
		}
		var jobList pb.AgentJobList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &jobList) {
			pools.rejectInventory(msg.Event)
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		applyJobList(ctx, msg.Event, &jobList, pools, out)

	case "discovery_job", "backup_job":
		if pools.stopAccepting.Load() {
			slog.Info("dropping one-shot jobs during "+intakeStopReason(ctx), "event", msg.Event)
			return false, nil
		}
		var jobList pb.AgentJobList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &jobList) {
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		slog.Info("received one-shot jobs", "event", msg.Event, "count", len(jobList.Jobs))
		for _, job := range jobList.Jobs {
			if job != nil {
				expandJobQueries(job)
				dispatchJob(ctx, job, pools, out)
			}
		}

	case "check_jobs":
		if pools.stopAccepting.Load() {
			refuseInventory(ctx, pools, out, msg.Event)
			return false, nil
		}
		var checkList pb.CheckList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &checkList) {
			pools.rejectInventory(msg.Event)
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		applyCheckList(ctx, msg.Event, &checkList, pools, out)

	case "restart":
		slog.Info("restart requested by server")
		return true, errRestartRequested

	case "update":
		var payload struct {
			URL      string `json:"url"`
			Checksum string `json:"checksum"`
			Version  string `json:"version"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil || payload.URL == "" || payload.Checksum == "" {
			slog.Error("invalid update payload")
			return false, nil
		}
		// The handle registers the update so process shutdown can cancel it
		// before the binary is replaced (see cancelActiveUpdate). Session
		// cancellation must not reach the update, hence WithoutCancel in
		// beginUpdate.
		update := beginUpdate(ctx)
		if update == nil {
			slog.Warn("self-update already in progress, ignoring duplicate")
			return false, nil
		}
		slog.Info("update requested", "url", sanitizeURL(payload.URL), "version", payload.Version)
		go func() {
			if err := doSelfUpdate(update.ctx, payload.URL, payload.Checksum, payload.Version); err != nil {
				slog.Error("self-update failed", "error", err)
				recordUpdateFailure(payload.Version, err)
			}
			update.finish()
			abortDrainedSession()
		}()

	default:
		slog.Debug("ignoring event", "event", msg.Event)
	}
	return false, nil
}

// intakeStopReason names why stopAccepting is set. The self-update drain and
// the shutdown drain both set it; only shutdown cancels the job context.
func intakeStopReason(ctx context.Context) string {
	if ctx.Err() != nil {
		return "shutdown"
	}
	return "self-update drain"
}

// refuseInventory handles an inventory frame that arrives after intake
// stopped. During the self-update drain the refusal is recorded and reported
// so the server re-pushes after the restart. During shutdown it is only
// logged: the process is exiting and the notice could not be sent anyway.
func refuseInventory(ctx context.Context, pools *jobPools, out *resultQueue, event string) {
	if ctx.Err() != nil {
		slog.Info("dropping " + event + " frame during shutdown")
		return
	}
	slog.Info("dropping " + event + " frame during self-update drain")
	pools.rejectInventory(event)
	reportInventoryRejection(ctx, out, event, "Refused "+event+" inventory during self-update drain")
}

// reportPayloadRejection sends a bounded error notice for a frame whose
// protobuf payload failed to decode (issue #2755). `inventory_rejection`
// marks the refusal as a schedule rejection — an authoritative "jobs" or
// "check_jobs" frame the agent could not accept — so the server records it
// and the applied-revision lag stays attributable to a cause instead of a
// silent drop.
func reportPayloadRejection(ctx context.Context, out *resultQueue, event string) {
	reportInventoryRejection(ctx, out, event, "Rejected malformed or oversized "+event+" payload")
}

// reportInventoryRejection reports a refused inventory frame — an
// authoritative "jobs" or "check_jobs" push the agent could not accept,
// either because the self-update drain stopped submissions or because its
// payload failed to decode. The frame name rides both the error notice
// and the heartbeat so the server can re-push the schedule.
func reportInventoryRejection(ctx context.Context, out *resultQueue, event, message string) {
	sendResult(ctx, out, "error", &pb.AgentError{
		Message:            message,
		Timestamp:          time.Now().Unix(),
		InventoryRejection: event,
	}, "")
}
func splitRecurringJobs(jobs []*pb.AgentJob) (recurring, oneShot []*pb.AgentJob) {
	recurring = make([]*pb.AgentJob, 0, len(jobs))
	oneShot = make([]*pb.AgentJob, 0, len(jobs))
	for _, job := range jobs {
		if job == nil {
			slog.Error("job dropped, payload contained a nil job")
			continue
		}
		if recurringJob(job) {
			recurring = append(recurring, job)
		} else {
			oneShot = append(oneShot, job)
		}
	}
	return recurring, oneShot
}

func recurringJob(job *pb.AgentJob) bool {
	return job.IntervalSeconds > 0
}

// decodeBinaryPayload unwraps the base64 protobuf a server push carries in its
// {"binary": ...} payload and unmarshals it into msg. Returns false and logs
// once if the payload is malformed or implausibly large.
func decodeBinaryPayload(event string, raw json.RawMessage, msg proto.Message) bool {
	var payload struct {
		Binary *string `json:"binary"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		slog.Error("decode payload", "event", event, "error", err)
		return false
	}
	if payload.Binary == nil {
		slog.Error("payload missing binary string", "event", event)
		return false
	}
	if len(*payload.Binary) > maxEncodedJobPayloadBytes {
		slog.Error("payload too large", "event", event, "size", len(*payload.Binary), "max", maxEncodedJobPayloadBytes)
		return false
	}
	bin, err := decodeBase64(*payload.Binary)
	if err != nil {
		slog.Error("decode base64", "event", event, "error", err)
		return false
	}
	// Clear the decoded buffer after unmarshalling job credentials. The
	// protobuf fields themselves are Go strings and remain immutable until the
	// protocol represents credentials as byte slices.
	defer clear(bin)
	if err := proto.Unmarshal(bin, msg); err != nil {
		slog.Error("unmarshal payload", "event", event, "error", err)
		return false
	}
	return true
}

// retryCeiling doubles the backoff ceiling, capped at maxRetryDelay. A
// non-positive start is normalized to initialRetryDelay first. The jitter
// lives in reconnectDelay: the ceiling itself stays deterministic.
func retryCeiling(current time.Duration) time.Duration {
	if current <= 0 {
		current = initialRetryDelay
	}
	return min(current*2, maxRetryDelay)
}

// reconnectDelay draws the wait before the next dial. A session that
// stayed up past successfulConnectionThreshold earns a first retry spread
// uniformly over [initialRetryDelay/2, 5*initialRetryDelay) so a fleet
// dropped together does not redial in the same second. Sustained failures
// get full jitter under the doubling ceiling. A refusal the server cannot
// heal draws from the refusal window instead.
func reconnectDelay(healthy, refused bool, ceiling time.Duration) time.Duration {
	switch {
	case refused:
		return uniformDelay(minRefusalDelay, maxRefusalDelay)
	case healthy:
		return uniformDelay(initialRetryDelay/2, initialRetryDelay*5)
	default:
		return uniformDelay(0, ceiling)
	}
}

// uniformDelay draws a duration in [lo, hi); a non-positive span returns
// lo exactly so degenerate test settings cannot panic the draw.
func uniformDelay(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rand.Int64N(int64(hi-lo)))
}

// refusedError marks a session failure the server will not heal on its
// own: a rejected join, or an HTTP 401/403 on the upgrade. The reconnect
// loop backs off to the refusal window rather than hammering a dead
// credential every couple of seconds.
type refusedError struct{ err error }

func (e refusedError) Error() string { return e.err.Error() }
func (e refusedError) Unwrap() error { return e.err }

// isRefused reports whether err marks a refusal, through any wrapping.
func isRefused(err error) bool {
	var re refusedError
	return errors.As(err, &re)
}
