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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

var osExit = os.Exit
var doSelfUpdate = selfUpdate

var errRestartRequested = fmt.Errorf("restart requested")

const maxJobPayloadBytes = 4 << 20 // 4 MB — well above any legitimate job list

// channelMsg is the WebSocket channel message format (JSON wrapper around binary protobuf).
type channelMsg struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
}

// runAgent connects to the server and runs the event loop with reconnect.
func runAgent(ctx context.Context, wsURL, token string) {
	baseURL := strings.TrimRight(wsURL, "/")
	retryDelay := time.Second
	maxRetry := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := runSession(ctx, baseURL, token)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRestartRequested) {
			osExit(0)
			return
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
func runSession(ctx context.Context, baseURL, token string) error {
	endpoint := baseURL + "/socket/agent/websocket"
	slog.Info("connecting", "url", sanitizeURL(endpoint))

	ws, err := WSDial(endpoint)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = ws.Close() }()

	agentID := fmt.Sprintf("agent-%d", time.Now().Unix())
	topic := "agent:" + agentID

	slog.Info("connected", "agent_id", agentID)

	// Channel for serializing WebSocket writes
	writeCh := make(chan []byte, 10000)

	// Worker pools — bounded concurrency for each job type
	pools := &jobPools{
		snmp:     newWorkerPool(100),
		mikrotik: newWorkerPool(20),
		ping:     newWorkerPool(50),
	}

	// Result channels
	snmpResultCh := make(chan *pb.SnmpResult, 10000)
	mikrotikResultCh := make(chan *pb.MikrotikResult, 5000)
	credTestResultCh := make(chan *pb.CredentialTestResult, 5000)
	monitoringCheckCh := make(chan *pb.MonitoringCheck, 10000)

	// Ref counter for outbound messages
	var refCounter atomic.Uint64
	refCounter.Store(1)

	nextRef := func() string {
		return strconv.FormatUint(refCounter.Add(1), 10)
	}

	sendMsg := func(event string, payload json.RawMessage) {
		msg := channelMsg{
			Topic:   topic,
			Event:   event,
			Payload: payload,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			slog.Error("marshal message", "error", err)
			return
		}
		select {
		case writeCh <- data:
		default:
			slog.Warn("write channel full, dropping message", "event", event)
		}
	}

	bufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 0, 4096)
			return &b
		},
	}

	sendBinaryResult := func(event string, msg proto.Message) {
		bp := bufPool.Get().(*[]byte)
		buf := (*bp)[:0]
		bin, err := proto.MarshalOptions{}.MarshalAppend(buf, msg)
		if err != nil {
			slog.Error("marshal protobuf", "error", err)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(bin)
		full := (*bp)[:cap(*bp)]
		zeroBytes(full)
		*bp = full[:0]
		bufPool.Put(bp)
		payload, _ := json.Marshal(map[string]string{"binary": encoded})
		sendMsg(event, payload)
	}

	// Join channel
	joinPayload, _ := json.Marshal(map[string]string{"token": token})
	joinMsg := channelMsg{
		Topic:   topic,
		Event:   "phx_join",
		Payload: joinPayload,
		Ref:     strPtr("1"),
	}
	joinData, _ := json.Marshal(joinMsg)
	if err := ws.WriteText(joinData); err != nil {
		return fmt.Errorf("send join: %w", err)
	}
	slog.Debug("sent channel join request")

	// Writer goroutine - serializes all writes to the WebSocket
	var writerWg sync.WaitGroup
	writeErrCh := make(chan error, 1)
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for data := range writeCh {
			if err := ws.WriteText(data); err != nil {
				slog.Error("websocket write", "error", err)
				select {
				case writeErrCh <- err:
				default:
				}
				return
			}
		}
	}()

	// Reader goroutine - reads messages and dispatches
	msgCh := make(chan []byte, 100)
	errCh := make(chan error, 1)
	go func() {
		for {
			data, _, err := ws.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- data
		}
	}()

	heartbeatTicker := time.NewTicker(60 * time.Second)
	defer heartbeatTicker.Stop()
	channelHeartbeatTicker := time.NewTicker(25 * time.Second)
	defer channelHeartbeatTicker.Stop()
	flushTicker := time.NewTicker(100 * time.Millisecond)
	defer flushTicker.Stop()
	startTime := time.Now()

	defer func() {
		pools.snmp.stop()
		pools.mikrotik.stop()
		pools.ping.stop()
		close(writeCh)
		writerWg.Wait()
	}()

	var snmpBatch []*pb.SnmpResult

	flushSnmpBatch := func() {
		if len(snmpBatch) == 0 {
			return
		}
		for _, r := range snmpBatch {
			sendBinaryResult("result", r)
		}
		slog.Info("flushed snmp results", "count", len(snmpBatch))
		snmpBatch = snmpBatch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown signal, closing connection")
			flushSnmpBatch()
			return nil

		case err := <-errCh:
			flushSnmpBatch()
			return fmt.Errorf("read: %w", err)

		case err := <-writeErrCh:
			flushSnmpBatch()
			return fmt.Errorf("write: %w", err)

		case data := <-msgCh:
			var msg channelMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				slog.Warn("invalid message", "error", err)
				continue
			}
			if handleMessage(ctx, msg, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh) {
				flushSnmpBatch()
				return errRestartRequested
			}

		case result := <-snmpResultCh:
			snmpBatch = append(snmpBatch, result)
			if len(snmpBatch) >= 50 {
				flushSnmpBatch()
			}

		case result := <-mikrotikResultCh:
			sendBinaryResult("mikrotik_result", result)
			slog.Info("sent mikrotik result", "device", result.DeviceId, "job", result.JobId)

		case result := <-credTestResultCh:
			sendBinaryResult("credential_test_result", result)
			slog.Info("sent credential test result", "test_id", result.TestId, "success", result.Success)

		case result := <-monitoringCheckCh:
			sendBinaryResult("monitoring_check", result)
			slog.Info("sent monitoring check", "device", result.DeviceId, "status", result.Status)

		case <-flushTicker.C:
			flushSnmpBatch()

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
			}
			slog.Debug("sent channel heartbeat", "ref", ref)
		}
	}
}

// handleMessage dispatches incoming channel messages.
// Returns true if the session should end (e.g. restart requested).
func handleMessage(
	ctx context.Context,
	msg channelMsg,
	pools *jobPools,
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
) bool {
	switch msg.Event {
	case "phx_reply":
		slog.Debug("channel reply", "topic", msg.Topic)

	case "jobs", "discovery_job", "backup_job":
		var payload struct {
			Binary string `json:"binary"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			slog.Error("decode job payload", "error", err)
			return false
		}
		if len(payload.Binary) > maxJobPayloadBytes {
			slog.Error("job payload too large", "size", len(payload.Binary), "max", maxJobPayloadBytes)
			return false
		}
		bin, err := base64.StdEncoding.DecodeString(payload.Binary)
		if err != nil {
			slog.Error("decode base64", "error", err)
			return false
		}
		var jobList pb.AgentJobList
		if err := proto.Unmarshal(bin, &jobList); err != nil {
			slog.Error("unmarshal job list", "error", err)
			return false
		}
		slog.Info("received jobs", "count", len(jobList.Jobs))
		for _, job := range jobList.Jobs {
			dispatchJob(ctx, job, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh)
		}

	case "restart":
		slog.Info("restart requested by server")
		return true

	case "update":
		var payload struct {
			URL      string `json:"url"`
			Checksum string `json:"checksum"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil || payload.URL == "" || payload.Checksum == "" {
			slog.Error("invalid update payload")
			return false
		}
		slog.Info("update requested", "url", payload.URL)
		if err := doSelfUpdate(payload.URL, payload.Checksum); err != nil {
			slog.Error("self-update failed", "error", err)
		}

	default:
		slog.Debug("ignoring event", "event", msg.Event)
	}
	return false
}

// jobPools holds the worker pools for each job type.
type jobPools struct {
	snmp     *workerPool
	mikrotik *workerPool
	ping     *workerPool
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
	default:
		ok = pools.snmp.submit(ctx, func() { executeSnmpJob(ctx, job, snmpResultCh) })
	}
	if !ok {
		slog.Warn("job dropped, pool full", "job_id", job.JobId)
	}
}

// nextBackoff doubles the current delay (capped at max) and adds up to 25% jitter.
func nextBackoff(current, maxDelay time.Duration) time.Duration {
	next := current * 2
	if next > maxDelay {
		next = maxDelay
	}
	jitter := time.Duration(rand.Int64N(int64(next / 4)))
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

func strPtr(s string) *string { return &s }
