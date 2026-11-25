// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
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
	t.Cleanup(stopPingEngine)

	ok := submitPingJob(context.Background(), &pb.AgentJob{
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
	t.Cleanup(stopPingEngine)

	out := newResultQueue(1)
	start := time.Now()
	ok := submitPingJob(context.Background(), &pb.AgentJob{
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

func TestPingEngineNilDeviceRejected(t *testing.T) {
	peTInstallFakeICMP(t)
	t.Cleanup(stopPingEngine)

	out := newResultQueue(1)
	done := make(chan struct{})
	ok := submitPingJob(context.Background(), &pb.AgentJob{JobId: "pe-nil"}, out, func() { close(done) })
	if ok {
		t.Error("submitPingJob accepted a nil-device job; want rejection")
	}
	select {
	case <-done:
		t.Error("rejected job must not fire done; the caller owns completion")
	default:
	}
}
