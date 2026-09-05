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

// successfulConnectionThreshold is how long a session must last before the
// reconnect backoff is considered stale and reset to initialRetryDelay.
var successfulConnectionThreshold = 30 * time.Second

// poolShutdownTimeout bounds how long session teardown waits for worker pools
// to drain before abandoning their in-flight jobs.
var poolShutdownTimeout = 5 * time.Second

const maxJobPayloadBytes = 4 << 20 // 4 MB — well above any legitimate job list

// resultQueueSize is the session's outbound result backlog. Workers drop a
// result rather than block once it is full; see resultSendTimeout. It is at
// least the 420 slots the six per-type queues held together (100 snmp + 20
// mikrotik + 100 credential test + 50 monitoring + 50 check + 100 lldp), so
// collapsing them cannot drop results a mixed burst used to survive.
const resultQueueSize = 512

// channelMsg is the WebSocket channel message format (JSON wrapper around binary protobuf).
type channelMsg struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
}

// runAgent connects to the server and runs the event loop with reconnect.
// traps may be nil when the trap listener is disabled.
func runAgent(ctx context.Context, wsURL, token string, traps <-chan *pb.SnmpTrap) {
	baseURL := strings.TrimRight(wsURL, "/")
	retryDelay := initialRetryDelay
	maxRetry := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sessionStart := time.Now()
		err := runSession(ctx, baseURL, token, traps)
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
	ws       *wsConn
	topic    string
	hostname string
	traps    <-chan *pb.SnmpTrap

	// ctx is cancelled as soon as either I/O goroutine fails, so blocked pool
	// submits unblock immediately instead of waiting for workers to finish.
	ctx    context.Context
	cancel context.CancelFunc

	writeCh    chan []byte
	msgCh      chan []byte
	errCh      chan error
	writeErrCh chan error
	readerDone chan struct{}
	writerDone chan struct{}

	// pools and results exist only once the channel join has been accepted;
	// see runSession.
	pools   *jobPools
	results resultQueue

	refCounter atomic.Uint64
}

// runSession runs a single WebSocket session. Returns when disconnected or ctx cancelled.
func runSession(ctx context.Context, baseURL, token string, traps <-chan *pb.SnmpTrap) error {
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
		ws:         ws,
		topic:      "agent:" + agentID,
		hostname:   hostname,
		traps:      traps,
		ctx:        sessionCtx,
		cancel:     sessionCancel,
		writeCh:    make(chan []byte, 256),
		msgCh:      make(chan []byte, 100),
		errCh:      make(chan error, 1),
		writeErrCh: make(chan error, 1),
		readerDone: make(chan struct{}),
		writerDone: make(chan struct{}),
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
	s.pools = &jobPools{
		snmp:     newWorkerPool(100),
		mikrotik: newWorkerPool(20),
		ping:     newWorkerPool(50),
		checks:   newWorkerPool(50),
	}
	s.results = make(resultQueue, resultQueueSize)

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
	for data := range s.writeCh {
		if err := s.ws.WriteText(s.ctx, data); err != nil {
			slog.Error("websocket write", "error", err)
			s.fail(s.writeErrCh, err)
			return
		}
	}
}

// fail publishes err — dropping it when an earlier error is already queued —
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

// stop tears the session down: socket I/O first, so a reader blocked on a
// server-requested reconnect returns, then the pools, then both goroutines.
func (s *session) stop() {
	s.cancel()
	_ = s.ws.Close()

	if s.pools != nil {
		for _, name := range s.pools.stop(poolShutdownTimeout) {
			slog.Warn("worker pool shutdown timed out, abandoning in-flight jobs", "pool", name)
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
	return enqueueWrite(s.ctx, s.writeCh, data, event)
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

// loop is the session event loop. ctx is the agent-wide context; the session's
// own context signals connection failure.
func (s *session) loop(ctx context.Context) error {
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	channelHeartbeatTicker := time.NewTicker(channelHeartbeatInterval)
	defer channelHeartbeatTicker.Stop()
	startTime := time.Now()

	for {
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
			shouldEnd, endErr := handleMessage(s.ctx, msg, s.topic, s.pools, s.results)
			if shouldEnd {
				return endErr
			}

		case result := <-s.results:
			if s.sendBinary(result.event, result.msg) {
				slog.Debug("sent result", "event", result.event)
			}

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
			if s.sendBinary("trap", trap) {
				slog.Info("sent snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid)
			}

		case <-heartbeatTicker.C:
			hb := &pb.AgentHeartbeat{
				Version:       version,
				UptimeSeconds: uint64(time.Since(startTime).Seconds()),
				Arch:          runtime.GOARCH,
				Hostname:      s.hostname,
				IpAddress:     s.ws.LocalIP(),
				Container:     runningInContainer(),
			}
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
			if enqueueWrite(s.ctx, s.writeCh, data, "heartbeat") {
				slog.Debug("sent channel heartbeat", "ref", ref)
			}
		}
	}
}

// enqueueWrite gives the session writer a bounded opportunity to accept a
// message. A full queue drops only that message; the writer's I/O timeout is
// responsible for detecting a wedged connection.
func enqueueWrite(ctx context.Context, writeCh chan<- []byte, data []byte, event string) bool {
	select {
	case writeCh <- data:
		return true
	case <-ctx.Done():
		return false
	default:
	}

	timer := time.NewTimer(writeQueueTimeout)
	defer timer.Stop()

	select {
	case writeCh <- data:
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
	out resultQueue,
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

	case "jobs", "discovery_job", "backup_job":
		var jobList pb.AgentJobList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &jobList) {
			return false, nil
		}
		slog.Info("received jobs", "count", len(jobList.Jobs))
		for _, job := range jobList.Jobs {
			dispatchJob(ctx, job, pools, out)
		}

	case "check_jobs":
		var checkList pb.CheckList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &checkList) {
			return false, nil
		}
		slog.Info("received checks", "count", len(checkList.Checks))
		for _, check := range checkList.Checks {
			executeCheck(ctx, check, pools, out)
		}

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
	if len(payload.Binary) > maxJobPayloadBytes {
		slog.Error("payload too large", "event", event, "size", len(payload.Binary), "max", maxJobPayloadBytes)
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

// outbound is one protobuf result addressed to a Phoenix channel event.
type outbound struct {
	event string
	msg   proto.Message
}

// resultQueue carries every worker result back to the session loop, which is
// the only goroutine allowed to write to the WebSocket.
type resultQueue chan outbound

// jobPools holds the worker pools for each job type.
type jobPools struct {
	snmp     *workerPool
	mikrotik *workerPool
	ping     *workerPool
	checks   *workerPool
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

// dispatchJob routes a job to the appropriate worker pool.
func dispatchJob(
	ctx context.Context,
	job *pb.AgentJob,
	pools *jobPools,
	out resultQueue,
) {
	slog.Info("starting job", "job_id", job.JobId, "type", job.JobType)

	var ok bool
	switch job.JobType {
	case pb.JobType_MIKROTIK:
		ok = pools.mikrotik.submit(ctx, func() { executeMikrotikJob(ctx, job, out) })
	case pb.JobType_TEST_CREDENTIALS:
		ok = pools.snmp.submit(ctx, func() { executeCredentialTest(ctx, job, out) })
	case pb.JobType_PING:
		ok = pools.ping.submit(ctx, func() { executePingJob(ctx, job, out) })
	case pb.JobType_LLDP_TOPOLOGY:
		ok = pools.snmp.submit(ctx, func() { executeLldpTopologyJob(ctx, job, out) })
	case pb.JobType_DISCOVER, pb.JobType_POLL:
		ok = pools.snmp.submit(ctx, func() { executeSnmpJob(ctx, job, out) })
	default:
		// A job type this build does not know about would otherwise be run as
		// an SNMP job, against a device config it may not even carry.
		slog.Error("job dropped, unknown job type", "job_id", job.JobId, "type", job.JobType)
		return
	}
	if !ok {
		slog.Warn("job dropped, pool full", "job_id", job.JobId)
	}
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

// resultSendTimeout bounds how long a worker waits to hand a result to the
// session loop. Exceeding it means the writer cannot keep up; dropping the
// result is better than pinning the worker.
const resultSendTimeout = 5 * time.Second

// sendResult queues a job result for the session's writer, or drops it if the
// queue stays full for resultSendTimeout.
func sendResult(ctx context.Context, out resultQueue, event string, msg proto.Message, jobID string) {
	sendCtx, cancel := context.WithTimeout(ctx, resultSendTimeout)
	defer cancel()
	select {
	case out <- outbound{event: event, msg: msg}:
	case <-sendCtx.Done():
		if ctx.Err() != nil {
			// Normal shutdown: the session ended while this job was running.
			slog.Debug("result dropped, session ended", "job_id", jobID, "event", event)
			return
		}
		slog.Error("result send timeout - agent overloaded", "job_id", jobID, "event", event)
	}
}

// executeCheck dispatches a check to the worker pool.
func executeCheck(ctx context.Context, check *pb.Check, pools *jobPools, out resultQueue) {
	ok := pools.checks.submit(ctx, func() {
		result := ExecuteCheck(ctx, check)
		slog.Info("check complete", "check", result.CheckId, "status", result.Status)
		sendResult(ctx, out, "check_result", result, check.Id)
	})
	if !ok {
		slog.Warn("check rejected (pool full)", "check_id", check.Id, "type", check.CheckType)
	}
}
