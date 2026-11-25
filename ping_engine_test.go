// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// peTInstallFakeICMP installs a scripted fake ICMP connection for one test
// and returns it, resetting the shared-socket registry on both ends so a
// stale real socket can never bypass the stub.
func peTInstallFakeICMP(t *testing.T) *tpTFakeICMPConn {
	t.Helper()
	conn := tpTNewFakeICMPConn()
	tpTUseFakeICMPConn(t, conn)
	return conn
}

// peTInjectEchoReply builds an echo reply from the given request bytes and
// injects it as though it arrived from the loopback peer.
func peTInjectEchoReply(t *testing.T, conn *tpTFakeICMPConn, req []byte) {
	t.Helper()
	reply := tpTEchoPacket(t, true, req, 0, 0)
	if reply == nil {
		t.Fatal("could not build echo reply from recorded request")
	}
	conn.injectPacket(reply, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// peTSubmitJob installs a fake ICMP connection and submits one ping job,
// returning the result queue the MonitoringCheck will land on.
func peTSubmitJob(t *testing.T, deviceID string, timeoutMs uint32) (*tpTFakeICMPConn, *resultQueue) {
	t.Helper()
	conn := peTInstallFakeICMP(t)
	out := newResultQueue(1)
	e := newPingEngine(context.Background())
	e.start()
	t.Cleanup(e.shutdown)

	ok := submitPingJob(context.Background(), e, &pb.AgentJob{
		JobId:         "pe-" + deviceID,
		DeviceId:      deviceID,
		SnmpDevice:    &pb.SnmpDevice{Ip: "127.0.0.1"},
		PingTimeoutMs: timeoutMs,
	}, out, func() {})
	if !ok {
		t.Fatal("submitPingJob rejected a job on an empty queue")
	}
	return conn, out
}

func TestPingEngineProbeSpacing(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	conn, out := peTSubmitJob(t, "pe-spacing", 3000)

	var sentAt [3]time.Time
	for i := range 3 {
		sent := tpTWaitSent(t, conn, i+1)
		sentAt[i] = time.Now()
		peTInjectEchoReply(t, conn, sent[i].pkt)
	}

	result := sshTReceiveMonitoringResult(t, out)
	if result.Status != "success" {
		t.Errorf("status: got %q, want %q", result.Status, "success")
	}
	if result.PacketLossPercent != 0 {
		t.Errorf("loss: got %v, want 0", result.PacketLossPercent)
	}
	if result.ResponseTimeMs <= 0 {
		t.Errorf("rtt: got %v, want > 0", result.ResponseTimeMs)
	}

	gap12 := sentAt[1].Sub(sentAt[0])
	gap23 := sentAt[2].Sub(sentAt[1])
	if gap12 < 150*time.Millisecond || gap12 > 400*time.Millisecond {
		t.Errorf("probe 0→1 spacing: got %v, want ~200ms", gap12)
	}
	if gap23 < 150*time.Millisecond || gap23 > 400*time.Millisecond {
		t.Errorf("probe 1→2 spacing: got %v, want ~200ms", gap23)
	}
}

func TestPingEnginePartialLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	conn, out := peTSubmitJob(t, "pe-loss", 800)

	// Reply to probes 0 and 1; probe 2's echo is never injected, so the
	// deadline must collect it as lost.
	for i := range 2 {
		sent := tpTWaitSent(t, conn, i+1)
		peTInjectEchoReply(t, conn, sent[i].pkt)
	}

	result := sshTReceiveMonitoringResult(t, out)
	if result.Status != "success" {
		t.Errorf("status: got %q, want %q (2 of 3 answered)", result.Status, "success")
	}
	wantLoss := 100.0 / 3.0
	if diff := result.PacketLossPercent - wantLoss; diff < -0.1 || diff > 0.1 {
		t.Errorf("loss: got %v, want ~%v", result.PacketLossPercent, wantLoss)
	}
	if result.ResponseTimeMs <= 0 {
		t.Errorf("rtt: got %v, want > 0", result.ResponseTimeMs)
	}
}

func TestPingEngineTotalLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	_, out := peTSubmitJob(t, "pe-dead", 200)

	result := sshTReceiveMonitoringResult(t, out)
	if result.Status != "failure" {
		t.Errorf("status: got %q, want %q", result.Status, "failure")
	}
	if result.PacketLossPercent != 100 {
		t.Errorf("loss: got %v, want 100", result.PacketLossPercent)
	}
}

// One shared round deadline used to skip the late probes entirely and
// shrink the rest: at a 200 ms timeout only one probe was ever sent, so a
// healthy device reported a constant 66% loss (issue 5161). Every probe now
// waits out the full timeout from its own send, so a 150 ms RTT reads as
// zero loss at any timeout the server accepts.
func TestPingEngineShortTimeoutNoFalseLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	for _, timeoutMs := range []uint32{200, 500, 1000} {
		t.Run(fmt.Sprintf("timeout_%dms", timeoutMs), func(t *testing.T) {
			conn, out := peTSubmitJob(t, fmt.Sprintf("pe-short-%d", timeoutMs), timeoutMs)
			for i := range pingProbeCount {
				sent := tpTWaitSent(t, conn, i+1)
				time.Sleep(150 * time.Millisecond)
				peTInjectEchoReply(t, conn, sent[i].pkt)
			}
			result := sshTReceiveMonitoringResult(t, out)
			if result.Status != "success" {
				t.Errorf("status: got %q, want success at %dms timeout", result.Status, timeoutMs)
			}
			if result.PacketLossPercent != 0 {
				t.Errorf("loss: got %v, want 0 at %dms timeout", result.PacketLossPercent, timeoutMs)
			}
		})
	}
}

func TestPingEngineReachabilityPublished(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	conn, out := peTSubmitJob(t, "pe-reach-up", 3000)
	sent := tpTWaitSent(t, conn, 1)
	peTInjectEchoReply(t, conn, sent[0].pkt)
	// Probes 1 and 2's echoes also need injecting for a clean 0% round.
	for i := 1; i < 3; i++ {
		s := tpTWaitSent(t, conn, i+1)
		peTInjectEchoReply(t, conn, s[i].pkt)
	}
	sshTReceiveMonitoringResult(t, out)

	entry, ok := lastDeviceReachability("pe-reach-up")
	if !ok {
		t.Fatal("reachability not published for a completed ping round")
	}
	if !entry.reachable {
		t.Error("reachable: got false, want true for a device that answered")
	}
	if entry.rttMs <= 0 {
		t.Errorf("rtt: got %v, want > 0", entry.rttMs)
	}

	// A device that never answers publishes reachable=false.
	_, outDown := peTSubmitJob(t, "pe-reach-down", 200)
	sshTReceiveMonitoringResult(t, outDown)
	entryDown, ok := lastDeviceReachability("pe-reach-down")
	if !ok {
		t.Fatal("reachability not published for a timed-out ping round")
	}
	if entryDown.reachable {
		t.Error("reachable: got true, want false for a dead device")
	}
	if entryDown.lossPct != 100 {
		t.Errorf("loss: got %v, want 100", entryDown.lossPct)
	}
}

func TestPingEngineSubmitNonBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	peTInstallFakeICMP(t)
	e := newPingEngine(context.Background())
	e.start()
	t.Cleanup(e.shutdown)

	out := newResultQueue(1)
	start := time.Now()
	ok := submitPingJob(context.Background(), e, &pb.AgentJob{
		JobId:         "pe-nonblocking",
		DeviceId:      "pe-nonblocking",
		SnmpDevice:    &pb.SnmpDevice{Ip: "127.0.0.1"},
		PingTimeoutMs: 3000,
	}, out, func() {})
	elapsed := time.Since(start)
	if !ok {
		t.Fatal("submitPingJob rejected a job on an empty queue")
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("submitPingJob blocked for %v; the engine must accept without holding a worker", elapsed)
	}
}

// A poller teardown must release every ping job the engine admitted but had
// not run yet: jobs sitting in submit lose their done callback otherwise,
// which wedges the per-target gate and every later ping for that device
// (issue 5167).
func TestPingEngineShutdownReleasesQueuedJobs(t *testing.T) {
	peTInstallFakeICMP(t)
	e := newPingEngine(context.Background())
	e.start()

	const n = 64
	var finished atomic.Int32
	done := func() { finished.Add(1) }

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			job := &pb.AgentJob{
				JobId:         fmt.Sprintf("drain-%d", i),
				DeviceId:      "drain-target",
				SnmpDevice:    &pb.SnmpDevice{Ip: "127.0.0.1"},
				PingTimeoutMs: 5000,
			}
			if !submitPingJob(context.Background(), e, job, newResultQueue(4), done) {
				done()
			}
		}(i)
	}
	wg.Wait()
	e.shutdown()

	if got := finished.Load(); got != n {
		t.Errorf("done ran %d times for %d jobs; a leaked job wedges its target gate", got, n)
	}
}

// Jobs still buffered on submit when the run loop stops get their done
// callback from the shutdown drain, in order.
func TestPingEngineShutdownDrainsSubmitBuffer(t *testing.T) {
	e := newPingEngine(context.Background())
	// Deliberately not started: everything queued stays on submit.
	const n = 4
	var finished atomic.Int32
	for i := 0; i < n; i++ {
		e.submit <- &pingJob{
			ctx:    context.Background(),
			cancel: func() {},
			done:   func() { finished.Add(1) },
		}
	}
	e.shutdown()
	if got := finished.Load(); got != n {
		t.Errorf("submit drain ran %d done callbacks, want %d", got, n)
	}
}

func TestPingEngineNilDeviceRejected(t *testing.T) {
	peTInstallFakeICMP(t)
	e := newPingEngine(context.Background())
	e.start()
	t.Cleanup(e.shutdown)

	out := newResultQueue(1)
	done := make(chan struct{})
	ok := submitPingJob(context.Background(), e, &pb.AgentJob{JobId: "pe-nil"}, out, func() { close(done) })
	if ok {
		t.Error("submitPingJob accepted a nil-device job; want rejection")
	}
	select {
	case <-done:
		t.Error("rejected job must not fire done; the caller owns completion")
	default:
	}
}

// A round whose probes all failed to leave the agent (sendto refused, a
// dead socket, a marshal error) measured nothing about the device. Before
// issue 5162 it was sent as a "failure" MonitoringCheck with 100% loss and
// an "unreachable" reachability hint; now it must report an agent error and
// leave the reachability entry untouched.
func TestPingEngineLocalSendFailureReportsAgentError(t *testing.T) {
	conn := peTInstallFakeICMP(t)
	conn.writeErr = syscall.EPERM
	out := newResultQueue(4)
	e := newPingEngine(context.Background())
	e.start()
	t.Cleanup(e.shutdown)

	publishReachability("pe-local", nil, true, 7, 0)
	defer func() {
		reachabilityMu.Lock()
		delete(reachByDevice, "pe-local")
		reachabilityMu.Unlock()
	}()

	ok := submitPingJob(context.Background(), e, &pb.AgentJob{
		JobId:         "pe-local",
		DeviceId:      "pe-local",
		SnmpDevice:    &pb.SnmpDevice{Ip: "10.0.0.1"},
		PingTimeoutMs: 1000,
	}, out, func() {})
	if !ok {
		t.Fatal("submitPingJob rejected a job on an empty queue")
	}

	agentErr := wantResult[*pb.AgentError](t, out, "error", 5*time.Second)
	if agentErr.DeviceId != "pe-local" || agentErr.JobId != "pe-local" {
		t.Errorf("agent error identity: got device=%q job=%q", agentErr.DeviceId, agentErr.JobId)
	}
	if agentErr.Message == "" {
		t.Error("agent error carried no message")
	}
	select {
	case extra := <-out.items:
		t.Fatalf("unexpected second result: %q", extra.event)
	default:
	}

	entry, ok := lastDeviceReachability("pe-local")
	if !ok || !entry.reachable || entry.rttMs != 7 {
		t.Fatalf("local send failure overwrote reachability: %+v %v", entry, ok)
	}
	if processMetrics.pingLocalErrors.Load() == 0 {
		t.Error("ping_local_errors metric was not counted")
	}
}

// A device the agent cannot reach by name still reports loss (the send
// left the agent), while an exec fallback whose ping binary cannot run is
// an agent fault: it must produce an agent error, not a down device
// (issue 5162).
func TestPingEngineExecFallbackLocalErrorReportsAgentError(t *testing.T) {
	// dev-1's hint is shared map state: clear anything an earlier test
	// published so the assertion below reads only this test's outcome.
	reachabilityMu.Lock()
	delete(reachByDevice, "dev-1")
	delete(reachByIP, "127.0.0.1")
	reachabilityMu.Unlock()

	orig := execPing
	execPing = func(context.Context, string, int) (float64, error) {
		return 0, &exec.Error{Name: "ping", Err: exec.ErrNotFound}
	}
	t.Cleanup(func() { execPing = orig })

	e, pj, out := newTestPingJob(t, true)
	e.fallback = make(chan *pingJob, 1)
	e.wg.Add(1)
	go e.runFallback()

	done := make(chan struct{}, 1)
	pj.done = func() { done <- struct{}{} }
	e.enqueueJob(pj)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exec round never finished")
	}

	agentErr := wantResult[*pb.AgentError](t, out, "error", 5*time.Second)
	if agentErr.DeviceId != "dev-1" {
		t.Errorf("agent error device: got %q, want dev-1", agentErr.DeviceId)
	}
	if _, ok := lastDeviceReachability("dev-1"); ok {
		t.Error("local exec failure published a reachability hint")
	}
}

// pingIsLocalExecError: only a failed exec or a non-"no reply" exit is an
// agent fault; a plain error from the ping output parse is device loss.
func TestPingIsLocalExecError(t *testing.T) {
	if !pingIsLocalExecError(&exec.Error{Name: "ping", Err: exec.ErrNotFound}) {
		t.Error("exec.Error must classify as local")
	}
	exit2 := exec.Command("sh", "-c", "exit 2").Run()
	if !pingIsLocalExecError(exit2) {
		t.Error("exit status 2 must classify as local")
	}
	exit1 := exec.Command("sh", "-c", "exit 1").Run()
	if pingIsLocalExecError(exit1) {
		t.Error("exit status 1 (no reply) must stay device loss")
	}
	if pingIsLocalExecError(errors.New("no time= line")) {
		t.Error("a parse failure must stay device loss")
	}
}

// firstLocalError scans for a marked probe and yields nil when none is
// flagged: a guard for callers that classify before counting (issue 5162).
func TestPingJobFirstLocalErrorNone(t *testing.T) {
	e, pj, _ := newTestPingJob(t, true)
	_ = e
	if err := pj.firstLocalError(); err != nil {
		t.Fatalf("firstLocalError with no flagged probes = %v, want nil", err)
	}
	sent := errors.New("sendto refused")
	pj.probes[1].localErr = true
	pj.probes[1].err = sent
	if err := pj.firstLocalError(); err != sent {
		t.Fatalf("firstLocalError = %v, want the flagged probe's error", err)
	}
}
