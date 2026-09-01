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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

var doSelfUpdate = selfUpdateContext

var errRestartRequested = fmt.Errorf("restart requested")
var errChannelReloaded = fmt.Errorf("channel reloaded")
var joinTimeout = 10 * time.Second
var heartbeatInterval = 60 * time.Second
var channelHeartbeatInterval = 25 * time.Second
var initialRetryDelay = time.Second

var agentIDCounter atomic.Uint64

// successfulConnectionThreshold is how long a session must last before the
// reconnect backoff is considered stale and reset to initialRetryDelay.
var successfulConnectionThreshold = 30 * time.Second

// poolShutdownTimeout bounds how long session teardown waits for worker pools
// to drain before abandoning their in-flight jobs.
var poolShutdownTimeout = 5 * time.Second

const maxJobPayloadBytes = 4 << 20 // 4 MB — well above any legitimate job list

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

// runSession runs a single WebSocket session. Returns when disconnected or ctx cancelled.
func runSession(ctx context.Context, baseURL, token string, traps <-chan *pb.SnmpTrap) error {
	endpoint := baseURL + "/socket/agent/websocket"
	slog.Info("connecting", "url", sanitizeURL(endpoint))

	ws, err := WSDial(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = ws.Close() }()

	// Include nanoseconds and a process-local sequence so immediate reconnects
	// cannot reuse a Phoenix topic, even when the clock has low resolution.
	agentID := newAgentID()
	topic := "agent:" + agentID

	slog.Info("connected", "agent_id", agentID)

	// Session-scoped context: cancelled on write/read errors so blocked
	// pool submits unblock immediately instead of waiting for workers to finish.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	// Channel for serializing WebSocket writes
	writeCh := make(chan []byte, 256)

	// Worker pools — bounded concurrency for each job type
	pools := &jobPools{
		snmp:     newWorkerPool(100),
		mikrotik: newWorkerPool(20),
		ping:     newWorkerPool(50),
		checks:   newWorkerPool(50),
	}

	// Result channels
	snmpResultCh := make(chan *pb.SnmpResult, 100)
	mikrotikResultCh := make(chan *pb.MikrotikResult, 20)
	credTestResultCh := make(chan *pb.CredentialTestResult, 100)
	monitoringCheckCh := make(chan *pb.MonitoringCheck, 50)
	checkResultCh := make(chan *pb.CheckResult, 50)
	lldpTopologyResultCh := make(chan *pb.LldpTopologyResult, 100)

	// Ref counter for outbound messages
	var refCounter atomic.Uint64
	refCounter.Store(1)

	nextRef := func() string {
		return strconv.FormatUint(refCounter.Add(1), 10)
	}

	sendMsg := func(event string, payload json.RawMessage) bool {
		msg := channelMsg{
			Topic:   topic,
			Event:   event,
			Payload: payload,
		}
		// Infallible: topic and event are strings and payload is always a
		// valid json.RawMessage produced by sendBinaryResult.
		data, _ := json.Marshal(msg)
		select {
		case writeCh <- data:
			return true
		default:
			slog.Error("write channel full, reconnecting", "event", event)
			sessionCancel()
			return false
		}
	}

	bufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 0, 4096)
			return &b
		},
	}

	sendBinaryResult := func(event string, msg proto.Message) bool {
		bp := bufPool.Get().(*[]byte)
		buf := (*bp)[:0]
		bin, err := proto.MarshalOptions{}.MarshalAppend(buf, msg)
		if err != nil {
			slog.Error("marshal protobuf", "error", err)
			bufPool.Put(bp)
			return false
		}
		encoded := base64.StdEncoding.EncodeToString(bin)
		// Zero the serialized protobuf data (may contain credentials).
		// MarshalAppend may return a new backing array, so zero both.
		zeroBytes(bin)
		full := (*bp)[:cap(*bp)]
		zeroBytes(full)
		*bp = full[:0]
		bufPool.Put(bp)
		payload, _ := json.Marshal(map[string]string{"binary": encoded})
		return sendMsg(event, payload)
	}

	// Reader goroutine — must start before join so we can receive the reply
	msgCh := make(chan []byte, 100)
	errCh := make(chan error, 1)
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			data, _, err := ws.ReadMessage(sessionCtx)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				sessionCancel()
				return
			}
			select {
			case msgCh <- data:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	go func() {
		<-sessionCtx.Done()
		_ = ws.Close()
	}()

	// Join channel
	joinPayload, _ := json.Marshal(map[string]string{"token": token})
	joinMsg := channelMsg{
		Topic:   topic,
		Event:   "phx_join",
		Payload: joinPayload,
		Ref:     strPtr("1"),
	}
	joinData, _ := json.Marshal(joinMsg)
	if err := ws.WriteText(sessionCtx, joinData); err != nil {
		return fmt.Errorf("send join: %w", err)
	}
	slog.Debug("sent channel join request")

	// Wait for join reply before entering main loop
	select {
	case data := <-msgCh:
		if err := validateJoinReply(data); err != nil {
			return err
		}
		slog.Info("channel joined")
	case err := <-errCh:
		return fmt.Errorf("read during join: %w", err)
	case <-time.After(joinTimeout):
		return fmt.Errorf("join timeout")
	}

	// Writer goroutine - serializes all writes to the WebSocket
	var writerWg sync.WaitGroup
	writeErrCh := make(chan error, 1)
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for data := range writeCh {
			if err := ws.WriteText(sessionCtx, data); err != nil {
				slog.Error("websocket write", "error", err)
				select {
				case writeErrCh <- err:
				default:
				}
				sessionCancel() // Unblock any stuck pool submits
				return
			}
		}
	}()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	channelHeartbeatTicker := time.NewTicker(channelHeartbeatInterval)
	defer channelHeartbeatTicker.Stop()
	startTime := time.Now()

	defer func() {
		// Stop socket I/O before waiting for either goroutine. In particular,
		// server-requested reconnects return while the reader is still blocked.
		sessionCancel()
		_ = ws.Close()

		for _, name := range pools.stop(poolShutdownTimeout) {
			slog.Warn("worker pool shutdown timed out, abandoning in-flight jobs", "pool", name)
		}
		close(writeCh)
		writerWg.Wait()
		readerWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown signal, closing connection")
			return nil

		case <-sessionCtx.Done():
			return fmt.Errorf("session cancelled")

		case err := <-errCh:
			return fmt.Errorf("read: %w", err)

		case err := <-writeErrCh:
			return fmt.Errorf("write: %w", err)

		case data := <-msgCh:
			var msg channelMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				slog.Debug("invalid message", "error", err)
				continue
			}
			shouldEnd, endErr := handleMessage(sessionCtx, msg, topic, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh, checkResultCh, lldpTopologyResultCh)
			if shouldEnd {
				return endErr
			}

		case result := <-snmpResultCh:
			sendBinaryResult("result", result)

		case result := <-mikrotikResultCh:
			sendBinaryResult("mikrotik_result", result)
			slog.Info("sent mikrotik result", "device", result.DeviceId, "job", result.JobId)

		case result := <-credTestResultCh:
			sendBinaryResult("credential_test_result", result)
			slog.Info("sent credential test result", "test_id", result.TestId, "success", result.Success)

		case result := <-monitoringCheckCh:
			sendBinaryResult("monitoring_check", result)
			slog.Info("sent monitoring check", "device", result.DeviceId, "status", result.Status)

		case result := <-checkResultCh:
			sendBinaryResult("check_result", result)
			slog.Info("sent check result", "check", result.CheckId, "status", result.Status)

		case result := <-lldpTopologyResultCh:
			sendBinaryResult("lldp_topology_result", result)
			slog.Info("sent LLDP topology result", "device", result.DeviceId, "neighbors", len(result.Neighbors))

		case trap, ok := <-traps:
			if !ok {
				slog.Warn("snmp trap listener stopped")
				traps = nil
				continue
			}
			if trap == nil {
				slog.Warn("ignoring nil snmp trap")
				continue
			}
			sendBinaryResult("trap", trap)
			slog.Info("sent snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid)

		case <-heartbeatTicker.C:
			hb := &pb.AgentHeartbeat{
				Version:       version,
				UptimeSeconds: uint64(time.Since(startTime).Seconds()),
				Arch:          runtime.GOARCH,
			}
			sendBinaryResult("heartbeat", hb)
			slog.Debug("sent heartbeat")

		case <-channelHeartbeatTicker.C:
			ref := nextRef()
			msg := channelMsg{
				Topic:   "phoenix",
				Event:   "heartbeat",
				Payload: json.RawMessage(`{}`),
				Ref:     &ref,
			}
			data, _ := json.Marshal(msg)
			select {
			case writeCh <- data:
			default:
				slog.Error("write channel full, reconnecting", "event", "heartbeat")
				sessionCancel()
			}
			slog.Debug("sent channel heartbeat", "ref", ref)
		}
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
		Status string `json:"status"`
	}
	if err := json.Unmarshal(reply.Payload, &status); err != nil {
		return fmt.Errorf("join reply payload: %w", err)
	}
	if status.Status != "ok" {
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
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
	checkResultCh chan<- *pb.CheckResult,
	lldpTopologyResultCh chan<- *pb.LldpTopologyResult,
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
			dispatchJob(ctx, job, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh, checkResultCh, lldpTopologyResultCh)
		}

	case "check_jobs":
		var checkList pb.CheckList
		if !decodeBinaryPayload(msg.Event, msg.Payload, &checkList) {
			return false, nil
		}
		slog.Info("received checks", "count", len(checkList.Checks))
		for _, check := range checkList.Checks {
			executeCheck(ctx, check, pools, checkResultCh)
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
		slog.Info("update requested", "url", sanitizeURL(payload.URL))
		if err := doSelfUpdate(ctx, payload.URL, payload.Checksum); err != nil {
			slog.Error("self-update failed", "error", err)
		}

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
	bin, err := base64.StdEncoding.DecodeString(payload.Binary)
	if err != nil {
		slog.Error("decode base64", "event", event, "error", err)
		return false
	}
	if err := proto.Unmarshal(bin, msg); err != nil {
		slog.Error("unmarshal payload", "event", event, "error", err)
		return false
	}
	return true
}

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
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
	checkResultCh chan<- *pb.CheckResult,
	lldpTopologyResultCh chan<- *pb.LldpTopologyResult,
) {
	slog.Info("starting job", "job_id", job.JobId, "type", job.JobType)

	var ok bool
	switch job.JobType {
	case pb.JobType_MIKROTIK:
		ok = pools.mikrotik.submit(ctx, func() { executeMikrotikJob(ctx, job, mikrotikResultCh) })
	case pb.JobType_TEST_CREDENTIALS:
		ok = pools.snmp.submit(ctx, func() { executeCredentialTest(ctx, job, credTestResultCh) })
	case pb.JobType_PING:
		ok = pools.ping.submit(ctx, func() { executePingJob(ctx, job, monitoringCheckCh) })
	case pb.JobType_LLDP_TOPOLOGY:
		ok = pools.snmp.submit(ctx, func() { executeLldpTopologyJob(ctx, job, lldpTopologyResultCh) })
	default:
		ok = pools.snmp.submit(ctx, func() { executeSnmpJob(ctx, job, snmpResultCh) })
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

// zeroBytes overwrites a byte slice with zeros.
// SECURITY: Go strings are immutable and cannot be zeroed in place. This utility
// is for zeroing byte slices (e.g., password buffers) to limit credential lifetime
// in memory. Credentials stored as Go strings (ssh.go, snmp.go, mikrotik.go)
// cannot benefit from this until the protocol layer supports []byte credentials.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// resultSendTimeout bounds how long a worker waits to hand a result to the
// session loop. Exceeding it means the writer cannot keep up; dropping the
// result is better than pinning the worker.
const resultSendTimeout = 5 * time.Second

// sendResult queues a job result for the session's writer, or drops it if the
// result channel stays full for resultSendTimeout.
func sendResult[T proto.Message](ctx context.Context, resultCh chan<- T, result T, jobID string) {
	sendCtx, cancel := context.WithTimeout(ctx, resultSendTimeout)
	defer cancel()
	select {
	case resultCh <- result:
	case <-sendCtx.Done():
		slog.Error("result send timeout - agent overloaded", "job_id", jobID)
	}
}

func strPtr(s string) *string { return &s }

// executeCheck dispatches a check to the worker pool.
func executeCheck(ctx context.Context, check *pb.Check, pools *jobPools, checkResultCh chan<- *pb.CheckResult) {
	ok := pools.checks.submit(ctx, func() {
		result := ExecuteCheck(ctx, check)
		select {
		case checkResultCh <- result:
		case <-ctx.Done():
		}
	})
	if !ok {
		slog.Warn("check rejected (pool full)", "check_id", check.Id, "type", check.CheckType)
	}
}
