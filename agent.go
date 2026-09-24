// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

var doSelfUpdate = selfUpdateContext
var getHostname = os.Hostname
var decodeBase64 = base64.StdEncoding.DecodeString

var errRestartRequested = errors.New("restart requested")
var errChannelReloaded = errors.New("channel reloaded")
var errSessionCancelled = errors.New("session cancelled")
var joinTimeout = 10 * time.Second
var heartbeatInterval = 60 * time.Second
var channelHeartbeatInterval = 25 * time.Second
var initialRetryDelay = time.Second
var writeQueueTimeout = 5 * time.Second

var agentIDCounter atomic.Uint64
var updateInProgress atomic.Bool
var processStart = time.Now()

// resultDropLogInterval bounds repeated spool saturation logs.
var resultDropLogInterval = time.Minute

// successfulConnectionThreshold is how long a session must last before the
// reconnect backoff is considered stale and reset to initialRetryDelay.
var successfulConnectionThreshold = 30 * time.Second

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

// channelMsg is the WebSocket channel message format (JSON wrapper around binary protobuf).
type channelMsg struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
}
type writeRequest struct {
	data []byte
	ack  chan error
}

// pendingResult is a spooled result awaiting the server's phx_reply. The
// server only replies to rejected messages (oversized payloads), so entries
// are pruned by age rather than removed on success.
type pendingResult struct {
	result outbound
	sentAt time.Time
}

// pendingReplyTTL expires phx_reply tracking for results the server never
// answered. Successful handle_in calls produce no reply, so entries would
// otherwise accumulate for the life of the session.
var pendingReplyTTL = 30 * time.Second

// runAgent connects to the server and runs the event loop with reconnect.
// traps may be nil when the trap listener is disabled.
func runAgent(ctx context.Context, wsURL, token string, traps <-chan *pb.SnmpTrap) {
	runAgentWithScheduling(ctx, wsURL, token, traps, true)
}

func runAgentWithScheduling(
	ctx context.Context,
	wsURL, token string,
	traps <-chan *pb.SnmpTrap,
	localScheduling bool,
) {
	baseURL := strings.TrimRight(wsURL, "/")
	results := newResultQueueForAgent(ctx, resultQueueSize)
	retryDelay := initialRetryDelay
	maxRetry := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sessionStart := time.Now()
		err := runSessionWithResultsAndScheduling(
			ctx,
			baseURL,
			token,
			traps,
			results,
			localScheduling,
		)
		sessionDuration := time.Since(sessionStart)

		// Reset backoff if session ran successfully for a while (indicates stable connection)
		if sessionDuration >= successfulConnectionThreshold {
			slog.Debug("resetting reconnect backoff after successful session",
				"duration", sessionDuration,
				"previous_delay", retryDelay)
			retryDelay = initialRetryDelay
		}

		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRestartRequested) {
			slog.Info("restart requested, reconnecting immediately")
			retryDelay = initialRetryDelay
			continue
		}
		if err != nil {
			slog.Error("agent disconnected", "error", err)
		}

		slog.Info("reconnecting", "delay", retryDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
		retryDelay = nextBackoff(retryDelay, maxRetry)
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

	// ctx is cancelled as soon as either I/O goroutine fails, so blocked pool
	// submits unblock immediately instead of waiting for workers to finish.
	ctx    context.Context
	cancel context.CancelFunc

	writeCh    chan writeRequest
	msgCh      chan []byte
	errCh      chan error
	writeErrCh chan error
	readerDone chan struct{}
	writerDone chan struct{}

	// pools and results exist only once the channel join has been accepted;
	// see runSession.
	pools     *jobPools
	scheduler *recurringScheduler
	results   *resultQueue
	notices   <-chan outbound

	refCounter atomic.Uint64

	// pending tracks result refs awaiting a server phx_reply so a rejected
	// delivery (e.g. an oversized payload) can be retried instead of being
	// acked on websocket write alone. Only the session loop touches it.
	pending map[string]pendingResult
}

// runSession runs one WebSocket session with local recurring scheduling.
func runSession(ctx context.Context, baseURL, token string, traps <-chan *pb.SnmpTrap) error {
	return runSessionWithResults(ctx, baseURL, token, traps, newResultQueueForAgent(ctx, resultQueueSize))
}

func runSessionWithResults(
	ctx context.Context,
	baseURL, token string,
	traps <-chan *pb.SnmpTrap,
	results *resultQueue,
) error {
	return runSessionWithResultsAndScheduling(ctx, baseURL, token, traps, results, true)
}

func runSessionWithResultsAndScheduling(
	ctx context.Context,
	baseURL, token string,
	traps <-chan *pb.SnmpTrap,
	results *resultQueue,
	localScheduling bool,
) error {
	endpoint := baseURL + "/socket/agent/websocket"
	slog.Info("connecting", "url", sanitizeURL(endpoint))

	ws, err := wsDial(ctx, endpoint)
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

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	s := &session{
		ws:              ws,
		topic:           "agent:" + agentID,
		hostname:        hostname,
		traps:           traps,
		localScheduling: localScheduling,
		ctx:             sessionCtx,
		cancel:          sessionCancel,
		writeCh:         make(chan writeRequest, 256),
		msgCh:           make(chan []byte, 100),
		errCh:           make(chan error, 1),
		writeErrCh:      make(chan error, 1),
		readerDone:      make(chan struct{}),
		writerDone:      make(chan struct{}),
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

	// Worker pools are created only now: 220 goroutines started before the
	// join would be abandoned by every early return above, and a revoked token
	// reconnects every few seconds.
	notices := make(chan outbound, overloadNoticeQueueSize)
	s.pools = &jobPools{
		snmp:            newWorkerPool(100),
		mikrotik:        newWorkerPool(20),
		ping:            newWorkerPool(50),
		checks:          newWorkerPool(50),
		notices:         notices,
		targets:         &targetGates{},
		localScheduling: localScheduling,
	}
	s.results = results
	s.notices = notices
	s.scheduler = newRecurringScheduler(s.ctx, realScheduleClock{})
	s.pools.scheduler = s.scheduler

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
		data, err := s.ws.ReadMessage(s.ctx)
		if err != nil {
			s.fail(s.errCh, err)
			return
		}
		select {
		case s.msgCh <- data:
		case <-s.ctx.Done():
			return
		}
	}
}

// write serializes every outbound frame; the session loop is its only producer.
func (s *session) write() {
	defer close(s.writerDone)
	for request := range s.writeCh {
		err := s.ws.WriteText(s.ctx, request.data)
		if request.ack != nil {
			request.ack <- err
		}
		if err != nil {
			slog.Error("websocket write", "error", err)
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
// first, then worker pools and the scheduler, then both I/O goroutines.
func (s *session) stop() {
	s.cancel()
	_ = s.ws.Close()

	if s.scheduler != nil {
		s.scheduler.cancelAll()
	}
	deadline := time.Now().Add(poolShutdownTimeout)
	if s.pools != nil {
		for _, name := range s.pools.stop(time.Until(deadline)) {
			slog.Warn("worker pool shutdown timed out, abandoning in-flight jobs", "pool", name)
		}
	}
	if s.scheduler != nil {
		remaining := time.Until(deadline)
		if remaining <= 0 || !s.scheduler.wait(remaining) {
			slog.Warn("recurring scheduler shutdown timed out")
		}
	}
	close(s.writeCh)
	<-s.writerDone
	<-s.readerDone
}

// join performs the phx_join exchange and validates the reply.
func (s *session) join(token string) error {
	joinPayload, _ := json.Marshal(map[string]string{"token": token})
	joinMsg := channelMsg{
		Topic:   s.topic,
		Event:   "phx_join",
		Payload: joinPayload,
		Ref:     new("1"),
	}
	joinData, _ := json.Marshal(joinMsg)
	if err := s.ws.WriteText(s.ctx, joinData); err != nil {
		return fmt.Errorf("send join: %w", err)
	}
	slog.Debug("sent channel join request")

	timer := time.NewTimer(joinTimeout)
	defer timer.Stop()
	select {
	case data := <-s.msgCh:
		if err := validateJoinReply(data); err != nil {
			return err
		}
		slog.Info("channel joined")
		return nil
	case err := <-s.errCh:
		return fmt.Errorf("read during join: %w", err)
	case <-timer.C:
		return errors.New("join timeout")
	}
}

func (s *session) nextRef() string {
	return strconv.FormatUint(s.refCounter.Add(1), 10)
}

// sendMsg queues a channel message for the writer.
func (s *session) sendMsg(event string, payload json.RawMessage) bool {
	msg := channelMsg{
		Topic:   s.topic,
		Event:   event,
		Payload: payload,
	}
	// Infallible: topic and event are strings and payload is always a valid
	// json.RawMessage produced by sendBinary.
	data, _ := json.Marshal(msg)
	return enqueueWrite(s.ctx, s.writeCh, writeRequest{data: data}, event)
}

// sendBinary queues a protobuf message inside the channel envelope.
func (s *session) sendBinary(event string, msg proto.Message) bool {
	bin, err := proto.Marshal(msg)
	if err != nil {
		slog.Error("marshal protobuf", "error", err)
		return false
	}
	encoded := base64.StdEncoding.EncodeToString(bin)
	payload, _ := json.Marshal(map[string]string{"binary": encoded})
	return s.sendMsg(event, payload)
}

// sendResultMsg writes a buffered result and waits until the WebSocket writer
// confirms the frame was handed to the connection. A failed session leaves
// the result unacknowledged so the next connection can retry it.
//
// The message carries a ref so the server's phx_reply can be correlated back
// to this result: a rejected delivery (oversized payload, decode failure) is
// retried once by handleResultReply instead of being silently dropped.
func (s *session) sendResultMsg(result outbound) error {
	ref := s.nextRef()
	msg := channelMsg{
		Topic:   s.topic,
		Event:   result.event,
		Payload: result.payload,
		Ref:     &ref,
	}
	data, _ := json.Marshal(msg)
	s.trackPending(ref, result)
	ack := make(chan error, 1)
	if !enqueueWrite(s.ctx, s.writeCh, writeRequest{data: data, ack: ack}, result.event) {
		delete(s.pending, ref)
		if s.ctx.Err() != nil {
			return s.sessionErr()
		}
		return fmt.Errorf("queue %s result for websocket write: timeout", result.event)
	}

	select {
	case err := <-ack:
		return resultWriteError(result.event, err)
	case <-s.ctx.Done():
		return s.resultWriteAfterCancellation(result.event, ack)
	}
}

func (s *session) resultWriteAfterCancellation(event string, ack <-chan error) error {
	if ok, err := completedResultWrite(event, ack); ok {
		return err
	}
	return s.sessionErr()
}

func completedResultWrite(event string, ack <-chan error) (bool, error) {
	select {
	case err := <-ack:
		return true, resultWriteError(event, err)
	default:
		return false, nil
	}
}

func resultWriteError(event string, err error) error {
	if err != nil {
		return fmt.Errorf("write %s result: %w", event, err)
	}
	return nil
}

func (s *session) deliverResult(result outbound) error {
	if err := s.sendResultMsg(result); err != nil {
		s.results.retry(result)
		return err
	}
	s.results.ack(result)
	slog.Debug("sent result", "event", result.event)
	return nil
}

// trackPending records a result under its message ref and expires entries the
// server never answered. Successful handle_in calls produce no phx_reply, so
// age — not success — is what bounds the map.
func (s *session) trackPending(ref string, result outbound) {
	if s.pending == nil {
		s.pending = make(map[string]pendingResult)
	}
	s.prunePending()
	s.pending[ref] = pendingResult{result: result, sentAt: time.Now()}
}

func (s *session) prunePending() {
	cutoff := time.Now().Add(-pendingReplyTTL)
	for ref, p := range s.pending {
		if p.sentAt.Before(cutoff) {
			delete(s.pending, ref)
		}
	}
}

// handleResultReply consumes a phx_reply addressed to this channel. A reply
// with an error status means the server rejected the result: it is retried
// once, then dropped loudly — the previous behaviour logged the rejection at
// debug while the spool slot had already been acked, so oversized results
// vanished with a false success.
func (s *session) handleResultReply(msg channelMsg) {
	if msg.Ref == nil {
		return
	}
	p, ok := s.pending[*msg.Ref]
	if !ok {
		return
	}
	delete(s.pending, *msg.Ref)

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
	if p.result.attempts == 0 {
		slog.Warn("server rejected result, retrying once",
			"event", p.result.event, "reason", reason)
		p.result.attempts++
		if !s.results.enqueue(p.result) {
			slog.Error("result retry dropped, spool full", "event", p.result.event)
		}
		return
	}
	slog.Error("server rejected result twice, dropping",
		"event", p.result.event, "reason", reason)
}

// sessionErr reports why the session context was cancelled. Both I/O
// goroutines publish their error before cancelling, so a non-blocking drain
// returns the real cause rather than whichever select case happened to win.
func (s *session) sessionErr() error {
	select {
	case err := <-s.errCh:
		return fmt.Errorf("read: %w", err)
	default:
	}
	select {
	case err := <-s.writeErrCh:
		return fmt.Errorf("write: %w", err)
	default:
	}
	return errSessionCancelled
}

func (s *session) heartbeat() *pb.AgentHeartbeat {
	localScheduling := s.localScheduling
	if s.pools != nil {
		localScheduling = s.pools.localScheduling
	}
	return &pb.AgentHeartbeat{
		Version:       version,
		UptimeSeconds: uint64(time.Since(processStart).Seconds()),
		Arch:          runtime.GOARCH,
		Hostname:      s.hostname,
		IpAddress:     s.ws.LocalIP(),
		Container:     runningInContainer(),
		SchedulesJobs: localScheduling,
	}
}

// loop is the session event loop. ctx is the agent-wide context; the session's
// own context signals connection failure.
func (s *session) loop(ctx context.Context) error {
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	channelHeartbeatTicker := time.NewTicker(channelHeartbeatInterval)
	defer channelHeartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown signal, closing connection")
			return nil
		default:
		}

		if result, ok := s.results.takeRetry(); ok {
			if err := s.deliverResult(result); err != nil {
				return err
			}
			continue
		}

		select {
		case <-ctx.Done():
			slog.Info("shutdown signal, closing connection")
			return nil

		case <-s.ctx.Done():
			return s.sessionErr()

		case err := <-s.errCh:
			return fmt.Errorf("read: %w", err)

		case err := <-s.writeErrCh:
			return fmt.Errorf("write: %w", err)

		case data := <-s.msgCh:
			var msg channelMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				slog.Debug("invalid message", "error", err)
				continue
			}
			if msg.Event == "phx_reply" && (msg.Topic == s.topic || msg.Topic == "phoenix") {
				s.handleResultReply(msg)
				continue
			}
			shouldEnd, endErr := handleMessage(s.ctx, msg, s.topic, s.pools, s.results)
			if shouldEnd {
				return endErr
			}

		case result := <-s.results.items:
			if err := s.deliverResult(result); err != nil {
				return err
			}

		case notice := <-s.notices:
			if err := s.sendResultMsg(notice); err != nil {
				return err
			}
			slog.Debug("sent overload notice", "event", notice.event)

		case trap, ok := <-s.traps:
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
			// them so a failed write is retried by the next connection.
			sendResult(s.results.agentCtx, s.results, "trap", trap, "")
			slog.Info("spooled snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid)

		case <-heartbeatTicker.C:
			hb := s.heartbeat()
			if s.sendBinary("heartbeat", hb) {
				slog.Debug("sent heartbeat")
			}

		case <-channelHeartbeatTicker.C:
			ref := s.nextRef()
			msg := channelMsg{
				Topic:   "phoenix",
				Event:   "heartbeat",
				Payload: json.RawMessage(`{}`),
				Ref:     &ref,
			}
			data, _ := json.Marshal(msg)
			if enqueueWrite(s.ctx, s.writeCh, writeRequest{data: data}, "heartbeat") {
				slog.Debug("sent channel heartbeat", "ref", ref)
			}
		}
	}
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

func validateJoinReply(data []byte) error {
	var reply channelMsg
	if err := json.Unmarshal(data, &reply); err != nil {
		return fmt.Errorf("join reply unmarshal: %w", err)
	}
	if reply.Event != "phx_reply" {
		return fmt.Errorf("expected phx_reply, got %s", reply.Event)
	}
	if reply.Ref == nil || *reply.Ref != "1" {
		return fmt.Errorf("join reply has unexpected ref")
	}
	var status struct {
		Status   string `json:"status"`
		Response struct {
			Reason string `json:"reason"`
		} `json:"response"`
	}
	if err := json.Unmarshal(reply.Payload, &status); err != nil {
		return fmt.Errorf("join reply payload: %w", err)
	}
	if status.Status != "ok" {
		if status.Response.Reason != "" {
			return fmt.Errorf("join rejected: %s (%s)", status.Status, status.Response.Reason)
		}
		return fmt.Errorf("join rejected: %s", status.Status)
	}
	return nil
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

	switch msg.Event {
	case "phx_reply":
		slog.Debug("channel reply", "topic", msg.Topic)

	case "phx_error", "phx_close":
		slog.Warn("phoenix channel ended, reconnecting",
			"event", msg.Event,
			"topic", msg.Topic)
		return true, errChannelReloaded

	case "jobs":
		var jobList pb.AgentJobList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &jobList) {
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		if !pools.localScheduling {
			pools.scheduler.replaceJobs(nil, pools, out)
			for _, job := range jobList.Jobs {
				if job != nil {
					dispatchJob(ctx, job, pools, out)
				}
			}
			break
		}

		recurring, oneShot := splitRecurringJobs(jobList.Jobs)
		slog.Info("received recurring jobs", "count", len(recurring))
		// A jobs frame containing only ad-hoc work is not an authoritative
		// inventory. Preserve scheduled assignments until an interval-bearing
		// or explicitly empty inventory arrives.
		if len(recurring) > 0 || len(jobList.Jobs) == 0 {
			pools.scheduler.replaceJobs(recurring, pools, out)
		}
		for _, job := range oneShot {
			slog.Info("received one-shot job", "job_id", job.JobId, "type", job.JobType)
			dispatchJob(ctx, job, pools, out)
		}

	case "discovery_job", "backup_job":
		var jobList pb.AgentJobList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &jobList) {
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		slog.Info("received one-shot jobs", "event", msg.Event, "count", len(jobList.Jobs))
		for _, job := range jobList.Jobs {
			dispatchJob(ctx, job, pools, out)
		}

	case "check_jobs":
		var checkList pb.CheckList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &checkList) {
			reportPayloadRejection(ctx, out, msg.Event)
			return false, nil
		}
		if !pools.localScheduling {
			pools.scheduler.replaceChecks(nil, pools, out)
			for _, check := range checkList.Checks {
				if check != nil {
					_ = submitCheck(ctx, check, pools, out, func() {}, false)
				}
			}
			break
		}
		slog.Info("received recurring checks", "count", len(checkList.Checks))
		pools.scheduler.replaceChecks(checkList.Checks, pools, out)

	case "restart":
		slog.Info("restart requested by server")
		return true, errRestartRequested

	case "update":
		var payload struct {
			URL      string `json:"url"`
			Checksum string `json:"checksum"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil || payload.URL == "" || payload.Checksum == "" {
			slog.Error("invalid update payload")
			return false, nil
		}
		if !updateInProgress.CompareAndSwap(false, true) {
			slog.Warn("self-update already in progress, ignoring duplicate")
			return false, nil
		}
		updateCtx := context.WithoutCancel(ctx)
		slog.Info("update requested", "url", sanitizeURL(payload.URL))
		go func() {
			defer updateInProgress.Store(false)
			if err := doSelfUpdate(updateCtx, payload.URL, payload.Checksum); err != nil {
				slog.Error("self-update failed", "error", err)
			}
		}()

	default:
		slog.Debug("ignoring event", "event", msg.Event)
	}
	return false, nil
}

func reportPayloadRejection(ctx context.Context, out *resultQueue, event string) {
	sendResult(ctx, out, "error", &pb.AgentError{
		Message:   "Rejected malformed or oversized " + event + " payload",
		Timestamp: time.Now().Unix(),
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
		Binary string `json:"binary"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		slog.Error("decode payload", "event", event, "error", err)
		return false
	}
	if len(payload.Binary) > maxEncodedJobPayloadBytes {
		slog.Error("payload too large", "event", event, "size", len(payload.Binary), "max", maxEncodedJobPayloadBytes)
		return false
	}
	bin, err := decodeBase64(payload.Binary)
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

// outbound is one pre-encoded protobuf result addressed to a Phoenix channel
// event. Keeping the payload process-wide allows a later WebSocket session to
// retry it without retaining mutable executor state. discovery marks results
// eligible for the reserved spool lane; discSlot records which lane's slot the
// result holds so ack can release it.
type outbound struct {
	event     string
	payload   json.RawMessage
	discovery bool
	discSlot  bool
	// attempts counts server-rejected deliveries; handleResultReply retries
	// the first rejection and drops the second.
	attempts int
}

// resultQueue is a bounded process-wide spool. A slot remains reserved while
// the session writer has a result in flight. Failed writes use a dedicated
// one-item retry lane so they remain ahead of newer queued measurements.
//
// A quarter of the slots are reserved for discovery results so a flood of
// pings and checks cannot evict them; discovery results overflow into the
// general lane when their reserve is exhausted, never the reverse.
type resultQueue struct {
	items       chan outbound
	retries     chan outbound
	slots       chan struct{}
	discSlots   chan struct{}
	agentCtx    context.Context
	dropped     atomic.Uint64
	lastDropLog atomic.Int64
}

func newResultQueueForAgent(agentCtx context.Context, size int) *resultQueue {
	discovery := size / 4
	return &resultQueue{
		items:     make(chan outbound, size),
		retries:   make(chan outbound, 1),
		slots:     make(chan struct{}, size-discovery),
		discSlots: make(chan struct{}, discovery),
		agentCtx:  agentCtx,
	}
}

func (q *resultQueue) enqueue(result outbound) bool {
	if result.discovery {
		select {
		case q.discSlots <- struct{}{}:
			result.discSlot = true
			q.items <- result
			return true
		default:
		}
	}
	select {
	case q.slots <- struct{}{}:
		// A requeued discovery result can land here when its reserved lane
		// is full; the flag must record the lane actually taken or ack
		// releases the wrong token.
		result.discSlot = false
		q.items <- result
		return true
	default:
		return false
	}
}

func (q *resultQueue) ack(result outbound) {
	if result.discSlot {
		<-q.discSlots
		return
	}
	<-q.slots
}

// retry is intentionally blocking. The session loop calls it only for the
// single result previously removed from items/retries, then immediately ends
// the failed session, so the one-slot lane is necessarily empty.
func (q *resultQueue) retry(result outbound) {
	q.retries <- result
}

func (q *resultQueue) takeRetry() (outbound, bool) {
	select {
	case result := <-q.retries:
		return result, true
	default:
		return outbound{}, false
	}
}

// jobPools holds the worker pools for each job type and the per-target
// semaphores that serialize jobs for the same device across all of them.
type jobPools struct {
	snmp            *workerPool
	mikrotik        *workerPool
	ping            *workerPool
	checks          *workerPool
	notices         chan<- outbound
	scheduler       *recurringScheduler
	targets         *targetGates
	localScheduling bool
}

func (p *jobPools) stop(timeout time.Duration) []string {
	pools := map[string]*workerPool{
		"snmp": p.snmp, "mikrotik": p.mikrotik, "ping": p.ping, "checks": p.checks,
	}
	done := make(chan string, len(pools))
	for name, pool := range pools {
		go func() {
			pool.stop()
			done <- name
		}()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(pools) > 0 {
		select {
		case name := <-done:
			delete(pools, name)
		case <-timer.C:
			timedOut := make([]string, 0, len(pools))
			for name := range pools {
				timedOut = append(timedOut, name)
			}
			slices.Sort(timedOut)
			return timedOut
		}
	}
	return nil
}

// dispatchJob routes a one-shot job to the appropriate worker pool.
func dispatchJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
) {
	_ = submitJob(ctx, job, pools, out, func() {}, false)
}

func submitJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out *resultQueue,
	done func(),
	wait bool,
) bool {
	slog.Info("starting job", "job_id", job.JobId, "type", job.JobType)

	task := func(execute func()) func() {
		return func() {
			defer done()
			if ctx.Err() != nil {
				return
			}
			execute()
		}
	}

	var pool *workerPool
	var execute func()
	switch job.JobType {
	case pb.JobType_MIKROTIK:
		pool = pools.mikrotik
		execute = func() { executeMikrotikJob(ctx, job, out) }
	case pb.JobType_TEST_CREDENTIALS:
		pool = pools.snmp
		execute = func() { executeCredentialTest(ctx, job, out) }
	case pb.JobType_CREDENTIAL_PROBE:
		pool = pools.snmp
		execute = func() { executeCredentialProbe(ctx, job, out) }
	case pb.JobType_PING:
		pool = pools.ping
		execute = func() { executePingJob(ctx, job, out) }
	case pb.JobType_LLDP_TOPOLOGY:
		pool = pools.snmp
		execute = func() { executeLldpTopologyJob(ctx, job, out) }
	case pb.JobType_DISCOVER, pb.JobType_POLL:
		pool = pools.snmp
		execute = func() { executeSnmpJob(ctx, job, out) }
	default:
		reportUnsupportedJob(ctx, pools.notices, job)
		return false
	}

	// Jitter spreads the start times of jobs pushed in one batch; the target
	// gate then serializes jobs for the same device across every pool.
	target := jobTargetKey(job)
	gated := func() {
		jitterDispatch(ctx, dispatchJitter())
		release := pools.targets.acquire(ctx, target)
		if release == nil {
			return
		}
		defer release()
		execute()
	}

	ok := pool.submitMode(ctx, task(gated), wait)
	if !ok {
		reportPoolRejection(ctx, pools.notices, job.DeviceId, job.JobId, job.JobType.String())
	}
	return ok
}

// jobTargetKey identifies the device a job runs against so jobs for the same
// target serialize. The device IP is preferred; jobs without one fall back to
// the server-assigned device ID, then the job ID. PING jobs get their own
// namespace: a stalled SNMP walk must not delay the outage signal a ping
// delivers.
func jobTargetKey(job *pb.AgentJob) string {
	prefix := ""
	if job.JobType == pb.JobType_PING {
		prefix = "ping:"
	}
	if job.SnmpDevice != nil && job.SnmpDevice.Ip != "" {
		return prefix + job.SnmpDevice.Ip
	}
	if job.MikrotikDevice != nil && job.MikrotikDevice.Ip != "" {
		return prefix + job.MikrotikDevice.Ip
	}
	// Probe jobs carry the target in their candidates (snmp_device is nil):
	// key on the shared address so a probe cannot run concurrently with a
	// poll or discovery on the same device.
	if job.CredentialProbe != nil && len(job.CredentialProbe.Candidates) > 0 &&
		job.CredentialProbe.Candidates[0].Ip != "" {
		return prefix + job.CredentialProbe.Candidates[0].Ip
	}
	if job.DeviceId != "" {
		return prefix + "device:" + job.DeviceId
	}
	return prefix + "job:" + job.JobId
}

// nextBackoff doubles the current delay (capped at max) and adds up to 25% jitter.
func nextBackoff(current, maxDelay time.Duration) time.Duration {
	if current <= 0 {
		current = initialRetryDelay
	}
	next := current * 2
	if next > maxDelay {
		next = maxDelay
	}
	jitterRange := int64(next / 4)
	if jitterRange <= 0 {
		return next
	}
	jitter := time.Duration(rand.Int64N(jitterRange))
	return next + jitter
}

func encodeOutbound(event string, msg proto.Message, jobID string) (outbound, bool) {
	bin, err := proto.Marshal(msg)
	if err != nil {
		slog.Error("marshal protobuf", "job_id", jobID, "event", event, "error", err)
		return outbound{}, false
	}
	encoded := base64.StdEncoding.EncodeToString(bin)
	payload, _ := json.Marshal(map[string]string{"binary": encoded})
	return outbound{event: event, payload: payload, discovery: isDiscoveryResult(msg)}, true
}

// isDiscoveryResult reports whether a result message carries discovery data
// and therefore qualifies for the reserved spool lane.
func isDiscoveryResult(msg proto.Message) bool {
	switch m := msg.(type) {
	case *pb.SnmpResult:
		return m.JobType == pb.JobType_DISCOVER || m.JobType == pb.JobType_NETWORK_SWEEP
	case *pb.LldpTopologyResult, *pb.NetworkSweepResult, *pb.SweepResult:
		return true
	default:
		return false
	}
}

// sendResult queues a completed measurement for at-most-once WebSocket
// delivery. Cancellation means no measurement was completed and is never
// translated into a failure result.
func sendResult(ctx context.Context, out *resultQueue, event string, msg proto.Message, jobID string) {
	if ctx.Err() != nil {
		if out.agentCtx.Err() != nil {
			slog.Debug("result dropped, agent stopped", "job_id", jobID, "event", event)
		} else {
			slog.Debug("result discarded, job cancelled", "job_id", jobID, "event", event)
		}
		return
	}
	result, ok := encodeOutbound(event, msg, jobID)
	if !ok {
		return
	}
	if out.enqueue(result) {
		return
	}
	if out.agentCtx.Err() != nil {
		slog.Debug("result dropped, agent stopped", "job_id", jobID, "event", event)
		return
	}
	out.reportDrop(jobID, event)
}

func (q *resultQueue) reportDrop(jobID, event string) {
	dropped := q.dropped.Add(1)
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
func reportUnsupportedJob(ctx context.Context, notices chan<- outbound, job *pb.AgentJob) {
	jobType := strconv.FormatInt(int64(job.JobType), 10)
	slog.Error("job dropped, unknown job type", "job_id", job.JobId, "type", jobType)
	reportJobRejection(
		ctx,
		notices,
		job.DeviceId,
		job.JobId,
		jobType,
		"unsupported job type "+jobType,
	)
}

func reportPoolRejection(
	ctx context.Context,
	notices chan<- outbound,
	deviceID, jobID, jobType string,
) {
	message := "worker pool overloaded; retry " + jobType + " job"
	slog.Warn("job rejected, pool full", "job_id", jobID, "type", jobType)
	reportJobRejection(ctx, notices, deviceID, jobID, jobType, message)
}

func reportJobRejection(
	ctx context.Context,
	notices chan<- outbound,
	deviceID, jobID, jobType, message string,
) {
	if ctx.Err() != nil {
		slog.Debug("job rejected, session ended", "job_id", jobID, "type", jobType)
		return
	}
	notice, ok := encodeOutbound("error", &pb.AgentError{
		DeviceId:  deviceID,
		JobId:     jobID,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}, jobID)
	if !ok {
		return
	}
	select {
	case notices <- notice:
	default:
		slog.Warn("job rejection notice queue full, notification dropped", "job_id", jobID, "type", jobType)
	}
}

func submitCheck(
	ctx context.Context,
	check *pb.Check,
	pools *jobPools,
	out *resultQueue,
	done func(),
	wait bool,
) bool {
	ok := pools.checks.submitMode(ctx, func() {
		defer done()
		if ctx.Err() != nil {
			return
		}
		result := ExecuteCheck(ctx, check)
		slog.Info("check complete", "check", result.CheckId, "status", result.Status)
		sendResult(ctx, out, "check_result", result, check.Id)
	}, wait)
	if !ok {
		reportPoolRejection(ctx, pools.notices, "", check.Id, "CHECK")
	}
	return ok
}
