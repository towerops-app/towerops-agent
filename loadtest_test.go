// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/loadtest"
	"github.com/towerops-app/towerops-agent/pb"
)

// loadTestEnabled keeps the multi-minute 3,000-device runs out of the normal
// suite; make loadtest (or TOWEROPS_LOADTEST=1 go test -run ...) opts in.
func loadTestEnabled() bool {
	_, ok := os.LookupEnv("TOWEROPS_LOADTEST")
	return ok
}

// TestLoadTestScenarios is the D6 benchmark entrypoint. Each subtest boots a
// real agent session loop against the loopback SNMP simulator and the stub
// Phoenix channel server, then fails on:
//   - any spool drop reported by resultQueueDroppedTotal,
//   - any missing or incomplete result in the scored window,
//   - any agent error notice,
//   - p95 schedule lag above five seconds.
//
// Scenario selection and sizing come from TOWEROPS_LOADTEST_* variables, so
// the same harness runs a one-device smoke check or the full matrix:
//
//	TOWEROPS_LOADTEST=1 \
//	TOWEROPS_LOADTEST_SCENARIOS=all_healthy_3000 \
//	go test -count=1 -timeout 30m -run '^TestLoadTestScenarios$' -v .
func TestLoadTestScenarios(t *testing.T) {
	if !loadTestEnabled() {
		t.Skip("set TOWEROPS_LOADTEST=1 (make loadtest) to run the D6 load benchmark")
	}

	scenarios := loadtest.DefaultScenarios()
	if requested := strings.TrimSpace(os.Getenv("TOWEROPS_LOADTEST_SCENARIOS")); requested != "" {
		var wanted []loadtest.Scenario
		for _, name := range strings.Split(requested, ",") {
			name = strings.TrimSpace(name)
			index := slices.IndexFunc(scenarios, func(s loadtest.Scenario) bool { return s.Name == name })
			if index < 0 {
				t.Fatalf("unknown TOWEROPS_LOADTEST_SCENARIOS entry %q (valid: %s)",
					name, strings.Join(scenarioNames(scenarios), ", "))
			}
			wanted = append(wanted, scenarios[index])
		}
		scenarios = wanted
	}
	if count, err := strconv.Atoi(os.Getenv("TOWEROPS_LOADTEST_DEVICES")); err == nil && count > 0 {
		for i := range scenarios {
			scenarios[i].Devices = count
		}
	}
	if percent, err := strconv.Atoi(os.Getenv("TOWEROPS_LOADTEST_DEAD_PERCENT")); err == nil && percent >= 0 && percent <= 100 {
		for i := range scenarios {
			scenarios[i].DeadSharePercent = percent
		}
	}
	if ms, err := strconv.Atoi(os.Getenv("TOWEROPS_LOADTEST_LATENCY_MS")); err == nil && ms >= 0 {
		for i := range scenarios {
			scenarios[i].LatencyMS = ms
		}
	}
	if percent, err := strconv.ParseFloat(os.Getenv("TOWEROPS_LOADTEST_LOSS_PERCENT"), 64); err == nil && percent >= 0 && percent <= 100 {
		for i := range scenarios {
			scenarios[i].LossPercent = percent
		}
	}
	if seconds, err := strconv.Atoi(os.Getenv("TOWEROPS_LOADTEST_INTERVAL_SECONDS")); err == nil && seconds > 0 {
		for i := range scenarios {
			scenarios[i].IntervalSeconds = uint32(seconds)
			scenarios[i].Warmup = time.Duration(seconds)*time.Second + 15*time.Second
			scenarios[i].Measure = time.Duration(seconds)*time.Second + 20*time.Second
		}
	}
	if value, err := time.ParseDuration(os.Getenv("TOWEROPS_LOADTEST_WARMUP")); err == nil && value > 0 {
		for i := range scenarios {
			scenarios[i].Warmup = value
		}
	}
	if value, err := time.ParseDuration(os.Getenv("TOWEROPS_LOADTEST_MEASURE")); err == nil && value > 0 {
		for i := range scenarios {
			scenarios[i].Measure = value
		}
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			runLoadScenario(t, scenario)
		})
	}
}

func scenarioNames(scenarios []loadtest.Scenario) []string {
	names := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		names = append(names, scenario.Name)
	}
	return names
}

// runLoadScenario boots one complete scenario and turns the harness metrics
// into the pass/fail decision.
func runLoadScenario(t *testing.T, scenario loadtest.Scenario) {
	t.Helper()
	quietLogs(t)

	changed, err := loadtest.RaiseFileLimit(uint64(scenario.Devices) + 256)
	if err != nil {
		t.Fatalf("raise RLIMIT_NOFILE for %d sockets: %v", scenario.Devices, err)
	}
	if changed {
		t.Logf("raised RLIMIT_NOFILE for %d virtual devices", scenario.Devices)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	simulator, err := loadtest.StartSimulator(ctx, scenario.SimulatorConfig())
	if err != nil {
		t.Fatalf("start SNMP simulator: %v", err)
	}
	defer simulator.Close()

	jobs := loadtest.BuildJobs(scenario.SimulatorConfig(), scenario.IntervalSeconds, simulator.Ports())
	server, err := loadtest.StartChannelServer(ctx, loadtest.ChannelOptions{
		Jobs:              jobs,
		Revision:          1,
		ChunkJobs:         500,
		UplinkBytesPerSec: scenario.UplinkBytesPerSec,
	})
	if err != nil {
		t.Fatalf("start stub channel server: %v", err)
	}
	defer server.Stop()

	// Drop totals are process-wide: zero them per scenario so a previous
	// subtest cannot mask this run. Any drop during warmup or measurement
	// fails; only schedule lag is scoped to the scored phase.
	processMetrics.snmpTimeouts.Store(0)
	processMetrics.skippedTicks.Store(0)
	resultQueueDroppedTotal.Store(0)
	trapDroppedTotal.Store(0)

	results := newResultQueueForAgentBytes(ctx, resultSpoolByteLimit())
	agentErr := make(chan error, 1)
	go func() {
		agentErr <- runLoadAgent(ctx, server.BaseURL(), results)
	}()

	deadline := time.Now().Add(30 * time.Second)
	for server.Joins() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("agent never joined the stub channel")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Warmup covers the first full wall-clock phase, including the deterministic
	// first-tick stagger. The scored window is the next complete phase.
	time.Sleep(scenario.Warmup)
	if scenario.DropFor > 0 {
		server.StartDrop(scenario.DropFor)
		joinedBefore := server.Joins()
		for server.Dropping() {
			time.Sleep(100 * time.Millisecond)
		}
		deadline := time.Now().Add(30 * time.Second)
		for server.Joins() == joinedBefore || !server.RevisionApplied() {
			if time.Now().After(deadline) {
				t.Fatal("agent did not reconnect after the 60s WebSocket outage")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	server.ResetLedger()
	resetScheduleLag()
	time.Sleep(scenario.Measure)

	cancel()
	select {
	case err := <-agentErr:
		if err != nil {
			t.Fatalf("agent loop ended with %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("agent loop did not drain and exit after shutdown")
	}

	report := server.Ledger().Evaluate(expectedResultKeys(jobs))
	dropped := resultQueueDroppedTotal.Load()
	lagMS, hasLag := processMetrics.scheduleLagP95()
	snapshot := processMetrics.snapshot()

	t.Logf("scenario=%s devices=%d simulator_requests=%d simulator_responses=%d "+
		"simulator_malformed=%d simulator_send_errors=%d simulator_dropped=%d "+
		"joins=%d results=%d completed=%d partial=%d snmp_timeouts=%d "+
		"skipped_ticks=%d lag_p95_ms=%d spool_depth=%d",
		scenario.Name, scenario.Devices,
		simulator.Stats().Requests.Load(), simulator.Stats().Responses.Load(),
		simulator.Stats().Malformed.Load(), simulator.Stats().SendErrors.Load(),
		simulator.Stats().Dropped.Load(),
		server.Joins(), report.ReceivedResults, report.CompletedKeys,
		report.PartialResults, snapshot.SNMPTimeouts, snapshot.SkippedTicks,
		lagMS, snapshot.SpoolDepth)

	if simulator.Stats().Responses.Load() == 0 {
		t.Fatalf("agent sent no successful SNMP request to the simulator (requests=%d)",
			simulator.Stats().Requests.Load())
	}
	if scenario.Name == "all_healthy_3000" {
		if report.PartialResults != 0 {
			t.Fatalf("healthy simulator produced %d partial results", report.PartialResults)
		}
		if snapshot.SNMPTimeouts != 0 {
			t.Fatalf("healthy simulator produced %d SNMP timeouts", snapshot.SNMPTimeouts)
		}
	}
	if dropped != 0 {
		t.Fatalf("spool dropped %d results (no result may be dropped)", dropped)
	}
	if len(report.AgentErrors) > 0 {
		t.Fatalf("agent reported %d errors, first: %s", len(report.AgentErrors), report.AgentErrors[0])
	}
	if len(report.MissingKeys) > 0 {
		limit := min(len(report.MissingKeys), 10)
		t.Fatalf("missing %d of %d expected results; first: %s",
			len(report.MissingKeys), len(expectedResultKeys(jobs)),
			strings.Join(report.MissingKeys[:limit], "; "))
	}
	if hasLag && lagMS > 5000 {
		t.Fatalf("p95 schedule lag %dms exceeds 5000ms", lagMS)
	}
}

// runLoadAgent mirrors runAgentWithScheduling, but owns the result spool so
// the harness can observe every result that was queued or dropped across
// reconnects. The process poller (scheduler, pools, inventory) follows the
// production lifetime across transport failures.
func runLoadAgent(ctx context.Context, baseURL string, results *resultQueue) error {
	var traps <-chan *pb.SnmpTrap
	stopJobSummary := startJobSummaryLogger(ctx)
	defer stopJobSummary()
	backoff := initialRetryDelay
	var poller *processPoller
	defer func() {
		if poller != nil {
			poller.stop()
		}
	}()

	for ctx.Err() == nil {
		if poller == nil || poller.stopped.Load() {
			poller = newProcessPoller(ctx, results, true)
		}
		sessionStart := time.Now()
		err := runSessionWithPoller(ctx, baseURL, "loadtest-token", traps, results, poller)
		sessionDuration := time.Since(sessionStart)
		healthy := sessionDuration >= successfulConnectionThreshold
		if healthy {
			backoff = initialRetryDelay
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errRestartRequested) || errors.Is(err, errSelfUpdateAborted) {
			poller.stop()
			poller = nil
			backoff = initialRetryDelay
			continue
		}
		poller.disconnected()
		if err != nil && !errors.Is(err, errChannelReloaded) {
			slog.Error("loadtest session failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(reconnectDelay(healthy, isRefused(err), backoff)):
		}
		backoff = retryCeiling(backoff)
	}
	return nil
}

// expectedResultKeys maps every assignment to one logical result identity.
func expectedResultKeys(jobs []*pb.AgentJob) map[string]string {
	expected := make(map[string]string, len(jobs))
	for _, job := range jobs {
		if job == nil {
			continue
		}
		switch job.JobType {
		case pb.JobType_POLL, pb.JobType_DISCOVER:
			expected["snmp:"+job.JobId] = job.DeviceId + " poll"
		case pb.JobType_PING:
			expected["ping:"+job.DeviceId] = job.DeviceId + " ping"
		}
	}
	return expected
}

// resetScheduleLag clears the bounded lag window so the scored p95 describes
// exactly the measurement phase.
func resetScheduleLag() {
	processMetrics.scheduleLagMu.Lock()
	processMetrics.scheduleLag = nil
	processMetrics.scheduleLagPos = 0
	processMetrics.scheduleLagFull = false
	processMetrics.scheduleLagMu.Unlock()
}

// quietLogs keeps 3,000 polling devices from writing 200 lines/s to the test
// transcript. Failure output above still identifies every broken contract.
func quietLogs(t *testing.T) {
	t.Helper()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError,
	})))
	t.Cleanup(func() { slog.SetDefault(previous) })
}

// Issue 5149: the server pushes every full-sync chunk back to back, faster
// than the shallow decode queue can drain. Refusing on a full queue used to
// lose chunks, and one lost chunk voids the whole atomic inventory
// assembly, leaving the agent connected but polling nothing. The loop now
// parks the frame and stops reading msgCh until the decoder accepts it, so
// every chunk applies and the heartbeat reports the revision.
func TestSessionAppliesFullSyncUnderDecodePressure(t *testing.T) {
	orig := heartbeatInterval
	defer func() { heartbeatInterval = orig }()
	heartbeatInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ports := make([]int, 120)
	for i := range ports {
		ports[i] = 40000 + i
	}
	jobs := loadtest.BuildJobs(loadtest.SimulatorConfig{
		DeviceCount: 120,
		Community:   "public",
		Interfaces:  30,
		WalkRoots:   19,
	}, 60, ports)

	server, err := loadtest.StartChannelServer(ctx, loadtest.ChannelOptions{
		Jobs: jobs, Revision: 1, ChunkJobs: 10,
	})
	if err != nil {
		t.Fatalf("start stub channel server: %v", err)
	}
	defer server.Stop()

	results := newResultQueueForAgentBytes(ctx, 1<<20)
	agentErr := make(chan error, 1)
	go func() { agentErr <- runLoadAgent(ctx, server.BaseURL(), results) }()

	deadline := time.Now().Add(30 * time.Second)
	for !server.RevisionApplied() {
		if time.Now().After(deadline) {
			t.Fatal("full sync never applied; a refused chunk voids the assembly")
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-agentErr:
		if err != nil {
			t.Fatalf("agent loop ended with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not stop on context cancel")
	}
}
