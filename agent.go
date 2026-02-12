package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
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
		if err != nil {
			slog.Error("agent disconnected", "error", err)
		}

		slog.Info("reconnecting", "delay", retryDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
		retryDelay = min(retryDelay*2, maxRetry)
	}
}

// runSession runs a single WebSocket session. Returns when disconnected or ctx cancelled.
func runSession(ctx context.Context, baseURL, token string) error {
	endpoint := baseURL + "/socket/agent/websocket"
	slog.Info("connecting", "url", endpoint)

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
		New: func() any { return make([]byte, 0, 4096) },
	}

	sendBinaryResult := func(event string, msg proto.Message) {
		buf := bufPool.Get().([]byte)[:0]
		bin, err := proto.MarshalOptions{}.MarshalAppend(buf, msg)
		if err != nil {
			slog.Error("marshal protobuf", "error", err)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(bin)
		bufPool.Put(bin[:0])
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
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for data := range writeCh {
			if err := ws.WriteText(data); err != nil {
				slog.Error("websocket write", "error", err)
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

		case data := <-msgCh:
			var msg channelMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				slog.Warn("invalid message", "error", err)
				continue
			}
			handleMessage(msg, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh)

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
func handleMessage(
	msg channelMsg,
	pools *jobPools,
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
) {
	switch msg.Event {
	case "phx_reply":
		slog.Debug("channel reply", "topic", msg.Topic)

	case "jobs", "discovery_job", "backup_job":
		var payload struct {
			Binary string `json:"binary"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			slog.Error("decode job payload", "error", err)
			return
		}
		bin, err := base64.StdEncoding.DecodeString(payload.Binary)
		if err != nil {
			slog.Error("decode base64", "error", err)
			return
		}
		var jobList pb.AgentJobList
		if err := proto.Unmarshal(bin, &jobList); err != nil {
			slog.Error("unmarshal job list", "error", err)
			return
		}
		slog.Info("received jobs", "count", len(jobList.Jobs))
		for _, job := range jobList.Jobs {
			dispatchJob(job, pools, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh)
		}

	case "restart":
		slog.Info("restart requested by server, exiting")
		osExit(0)

	case "update":
		var payload struct {
			URL      string `json:"url"`
			Checksum string `json:"checksum"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil || payload.URL == "" {
			slog.Error("invalid update payload")
			return
		}
		slog.Info("update requested", "url", payload.URL)
		if err := doSelfUpdate(payload.URL, payload.Checksum); err != nil {
			slog.Error("self-update failed", "error", err)
		}

	default:
		slog.Debug("ignoring event", "event", msg.Event)
	}
}

// jobPools holds the worker pools for each job type.
type jobPools struct {
	snmp     *workerPool
	mikrotik *workerPool
	ping     *workerPool
}

// dispatchJob routes a job to the appropriate worker pool.
func dispatchJob(
	job *pb.AgentJob,
	pools *jobPools,
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
) {
	slog.Info("starting job", "job_id", job.JobId, "type", job.JobType)

	switch job.JobType {
	case pb.JobType_MIKROTIK:
		pools.mikrotik.submit(func() { executeMikrotikJob(job, mikrotikResultCh) })
	case pb.JobType_TEST_CREDENTIALS:
		pools.snmp.submit(func() { executeCredentialTest(job, credTestResultCh) })
	case pb.JobType_PING:
		pools.ping.submit(func() { executePingJob(job, monitoringCheckCh) })
	default:
		pools.snmp.submit(func() { executeSnmpJob(job, snmpResultCh) })
	}
}

func strPtr(s string) *string { return &s }
