package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// phoenixMsg is the Phoenix channel message format (JSON wrapper around binary protobuf).
type phoenixMsg struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
}

// runAgent connects to the Phoenix server and runs the event loop with reconnect.
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
	defer ws.Close()

	agentID := fmt.Sprintf("agent-%d", time.Now().Unix())
	topic := "agent:" + agentID

	slog.Info("connected", "agent_id", agentID)

	// Channel for serializing WebSocket writes
	writeCh := make(chan []byte, 500)

	// Result channels
	snmpResultCh := make(chan *pb.SnmpResult, 1000)
	mikrotikResultCh := make(chan *pb.MikrotikResult, 1000)
	credTestResultCh := make(chan *pb.CredentialTestResult, 1000)
	monitoringCheckCh := make(chan *pb.MonitoringCheck, 1000)

	// Ref counter for outbound messages
	var refCounter atomic.Uint64
	refCounter.Store(1)

	nextRef := func() string {
		r := refCounter.Add(1)
		return fmt.Sprintf("%d", r)
	}

	sendMsg := func(event string, payload json.RawMessage) {
		msg := phoenixMsg{
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

	sendBinaryResult := func(event string, msg proto.Message) {
		bin, err := proto.Marshal(msg)
		if err != nil {
			slog.Error("marshal protobuf", "error", err)
			return
		}
		payload, _ := json.Marshal(map[string]string{"binary": base64.StdEncoding.EncodeToString(bin)})
		sendMsg(event, payload)
	}

	// Join channel
	joinPayload, _ := json.Marshal(map[string]string{"token": token})
	joinMsg := phoenixMsg{
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
	phxHeartbeatTicker := time.NewTicker(25 * time.Second)
	defer phxHeartbeatTicker.Stop()
	startTime := time.Now()

	defer func() {
		close(writeCh)
		writerWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown signal, closing connection")
			return nil

		case err := <-errCh:
			return fmt.Errorf("read: %w", err)

		case data := <-msgCh:
			var msg phoenixMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				slog.Warn("invalid message", "error", err)
				continue
			}
			handleMessage(msg, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh)

		case result := <-snmpResultCh:
			sendBinaryResult("result", result)
			slog.Info("sent snmp result", "device", result.DeviceId, "oids", len(result.OidValues))

		case result := <-mikrotikResultCh:
			sendBinaryResult("mikrotik_result", result)
			slog.Info("sent mikrotik result", "device", result.DeviceId, "job", result.JobId)

		case result := <-credTestResultCh:
			sendBinaryResult("credential_test_result", result)
			slog.Info("sent credential test result", "test_id", result.TestId, "success", result.Success)

		case result := <-monitoringCheckCh:
			sendBinaryResult("monitoring_check", result)
			slog.Info("sent monitoring check", "device", result.DeviceId, "status", result.Status)

		case <-heartbeatTicker.C:
			hb := &pb.AgentHeartbeat{
				Version:       version,
				UptimeSeconds: uint64(time.Since(startTime).Seconds()),
				Arch:          runtime.GOARCH,
			}
			sendBinaryResult("heartbeat", hb)
			slog.Debug("sent heartbeat")

		case <-phxHeartbeatTicker.C:
			ref := nextRef()
			msg := phoenixMsg{
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
			slog.Debug("sent phoenix heartbeat", "ref", ref)
		}
	}
}

// handleMessage dispatches incoming Phoenix channel messages.
func handleMessage(
	msg phoenixMsg,
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
			dispatchJob(job, snmpResultCh, mikrotikResultCh, credTestResultCh, monitoringCheckCh)
		}

	case "restart":
		slog.Info("restart requested by server, exiting")
		os.Exit(0)

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
		if err := selfUpdate(payload.URL, payload.Checksum); err != nil {
			slog.Error("self-update failed", "error", err)
		}

	default:
		slog.Debug("ignoring event", "event", msg.Event)
	}
}

// dispatchJob routes a job to the appropriate handler goroutine.
func dispatchJob(
	job *pb.AgentJob,
	snmpResultCh chan<- *pb.SnmpResult,
	mikrotikResultCh chan<- *pb.MikrotikResult,
	credTestResultCh chan<- *pb.CredentialTestResult,
	monitoringCheckCh chan<- *pb.MonitoringCheck,
) {
	slog.Info("starting job", "job_id", job.JobId, "type", job.JobType)

	switch job.JobType {
	case pb.JobType_MIKROTIK:
		go executeMikrotikJob(job, mikrotikResultCh)
	case pb.JobType_TEST_CREDENTIALS:
		go executeCredentialTest(job, credTestResultCh)
	case pb.JobType_PING:
		go executePingJob(job, monitoringCheckCh)
	default:
		// DISCOVER, POLL
		go executeSnmpJob(job, snmpResultCh)
	}
}

func strPtr(s string) *string { return &s }
