// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/towerops-app/towerops-agent/pb"
)

// fakePacketConn is a net.PacketConn stub for socket-buffer tests.
type fakePacketConn struct {
	syscallFn func() (syscall.RawConn, error)
	syscallOK bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{closed: make(chan struct{})}
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, errors.New("closed")
}
func (c *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *fakePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *fakePacketConn) LocalAddr() net.Addr              { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakePacketConn) SyscallConn() (syscall.RawConn, error) {
	if !c.syscallOK {
		return nil, errors.New("no syscall conn")
	}
	return c.syscallFn()
}

type fakeRawConn struct {
	controlErr error
	badFD      bool
}

func (r fakeRawConn) Control(fn func(fd uintptr)) error {
	if r.controlErr != nil {
		return r.controlErr
	}
	if r.badFD {
		fn(^uintptr(0)) // guaranteed invalid fd
	} else {
		fn(0)
	}
	return nil
}
func (fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error { return nil }

func TestRawICMPAdapter(t *testing.T) {
	pc := newFakePacketConn()
	a := rawICMPAdapter{pc: pc}
	n, err := a.WriteTo([]byte("ab"), &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil || n != 2 {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	if a.LocalAddr() == nil {
		t.Error("LocalAddr must proxy")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := a.ReadFrom(make([]byte, 8)); err == nil {
		t.Error("ReadFrom must surface close")
	}
}

func TestICMPListenPacketRawBranch(t *testing.T) {
	orig := listenICMPRaw
	t.Cleanup(func() { listenICMPRaw = orig })

	listenICMPRaw = func(network, address string) (net.PacketConn, error) {
		return newFakePacketConn(), nil
	}
	conn, err := icmpListenPacket("ip4:icmp", "")
	if err != nil {
		t.Fatalf("icmpListenPacket: %v", err)
	}
	if _, ok := conn.(rawICMPAdapter); !ok {
		t.Errorf("raw branch must wrap in rawICMPAdapter, got %T", conn)
	}
	_ = conn.Close()

	listenICMPRaw = func(network, address string) (net.PacketConn, error) {
		return nil, errors.New("EPERM")
	}
	if _, err := icmpListenPacket("ip4:icmp", ""); err == nil {
		t.Error("listen error must propagate")
	}
}

func TestApplySocketReadBufferPaths(t *testing.T) {
	// Non-syscall-capable connection.
	applySocketReadBuffer(&nonSyscallPacketConn{}, 4096, "plain")
	// SyscallConn failure.
	applySocketReadBuffer(&fakePacketConn{syscallOK: false}, 4096, "err")
	// Control failure.
	applySocketReadBuffer(&fakePacketConn{
		syscallOK: true,
		syscallFn: func() (syscall.RawConn, error) {
			return fakeRawConn{controlErr: errors.New("ctl")}, nil
		},
	}, 4096, "ctl-err")
	// setsockopt failure inside Control.
	applySocketReadBuffer(&fakePacketConn{
		syscallOK: true,
		syscallFn: func() (syscall.RawConn, error) {
			return fakeRawConn{badFD: true}, nil
		},
	}, 4096, "sock-err")
	// Success path on a real UDP socket (its fd exists).
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp4: %v", err)
	}
	defer func() { _ = udp.Close() }()
	applySocketReadBuffer(udp, 1<<20, "udp")
}

// nonSyscallPacketConn implements net.PacketConn without SyscallConn.
type nonSyscallPacketConn struct{}

func (nonSyscallPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (nonSyscallPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}
func (nonSyscallPacketConn) Close() error                     { return nil }
func (nonSyscallPacketConn) LocalAddr() net.Addr              { return nil }
func (nonSyscallPacketConn) SetDeadline(time.Time) error      { return nil }
func (nonSyscallPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (nonSyscallPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestSelectPingNetworkFallback(t *testing.T) {
	orig := icmpListenPacket
	t.Cleanup(func() {
		icmpListenPacket = orig
		closeSharedSockets()
	})

	closeSharedSockets() // engine tests may have cached a real UDP socket
	icmpListenPacket = func(network, address string) (icmpConn, error) {
		return nil, errors.New("unavailable")
	}
	network, needsExec := selectPingNetwork(true)
	if !needsExec || network != "" {
		t.Errorf("both sockets down must need exec, got %q %v", network, needsExec)
	}
	network, needsExec = selectPingNetwork(false)
	if !needsExec || network != "" {
		t.Errorf("v6 both sockets down must need exec, got %q %v", network, needsExec)
	}

	// Raw fails, UDP works → returns the UDP network. The unavailable cache
	// from the earlier scenario must be cleared first.
	closeSharedSockets()
	call := 0
	icmpListenPacket = func(network, address string) (icmpConn, error) {
		call++
		if call == 1 {
			return nil, errors.New("raw denied")
		}
		return tpTNewFakeICMPConn(), nil
	}
	network, needsExec = selectPingNetwork(true)
	if needsExec || network != "udp4" {
		t.Errorf("raw-fail must fall back to udp4, got %q %v", network, needsExec)
	}
	// Clean the socket map so other tests do not reuse the fake conn.
	closeSharedSockets()
}

func newTestPingJob(t *testing.T, needsExec bool) (*pingEngine, *pingJob, *resultQueue) {
	t.Helper()
	e := newPingEngine(context.Background())
	t.Cleanup(e.cancel)
	out := newResultQueueForAgentBytes(context.Background(), 1<<20)
	jobCtx, cancel := context.WithCancel(context.Background())
	pj := &pingJob{
		ctx:    jobCtx,
		cancel: cancel,
		job: &pb.AgentJob{
			JobId:      "ping-job",
			DeviceId:   "dev-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
		},
		out:       out,
		ip:        net.ParseIP("127.0.0.1"),
		isIPv4:    true,
		needsExec: needsExec,
		timeoutMs: 500,
		timestamp: time.Now().Unix(),
		deadline:  time.Now().Add(500 * time.Millisecond),
		probes:    make([]pingProbe, pingProbeCount),
	}
	return e, pj, out
}

func TestEnqueueJobPaths(t *testing.T) {
	t.Run("cancelled job returns immediately", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, false)
		done := make(chan struct{}, 1)
		pj.done = func() { done <- struct{}{} }
		pj.cancel()
		e.enqueueJob(pj)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("done not called")
		}
	})

	t.Run("exec job lands on the fallback queue", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, true)
		e.enqueueJob(pj)
		select {
		case got := <-e.fallback:
			if got != pj {
				t.Error("wrong job dequeued")
			}
		case <-time.After(time.Second):
			t.Fatal("job not on fallback queue")
		}
	})

	t.Run("full fallback queue drops the job", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, true)
		for i := 0; i < cap(e.fallback); i++ {
			e.fallback <- pj
		}
		done := make(chan struct{}, 1)
		pj.done = func() { done <- struct{}{} }
		e.enqueueJob(pj)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("done not called")
		}
		if !pj.finishing {
			t.Error("dropped job must be finishing")
		}
	})

	t.Run("icmp job schedules sends and deadline", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, false)
		e.enqueueJob(pj)
		e.mu.Lock()
		defer e.mu.Unlock()
		if _, live := e.live[pj]; !live {
			t.Fatal("job must be live")
		}
		if e.heap.Len() != pingProbeCount+1 {
			t.Errorf("heap = %d events, want %d", e.heap.Len(), pingProbeCount+1)
		}
		if e.timer == nil {
			t.Error("timer must be armed")
		}
	})
}

func TestExecPingRound(t *testing.T) {
	orig := execPing
	t.Cleanup(func() { execPing = orig })

	t.Run("cancelled job is cleaned up", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, true)
		done := make(chan struct{}, 1)
		pj.done = func() { done <- struct{}{} }
		e.live[pj] = struct{}{}
		pj.cancel()
		e.execPingRound(pj)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("done not called")
		}
		if _, live := e.live[pj]; live {
			t.Error("cancelled job must leave live")
		}
	})

	runRound := func(t *testing.T, replies int, wantStatus string) *pb.MonitoringCheck {
		e, pj, out := newTestPingJob(t, true)
		e.live[pj] = struct{}{}
		done := make(chan struct{}, 1)
		pj.done = func() { done <- struct{}{} }
		call := 0
		execPing = func(ctx context.Context, ip string, timeoutMs int) (float64, error) {
			call++
			if call <= replies {
				return 1.5, nil
			}
			return 0, errors.New("timeout")
		}
		e.execPingRound(pj)
		select {
		case res := <-out.items:
			var check pb.MonitoringCheck
			if err := proto.Unmarshal(res.protoPayload, &check); err != nil {
				t.Fatalf("result decode: %v", err)
			}
			return &check
		case <-time.After(2 * time.Second):
			t.Fatal("no result enqueued")
		}
		return nil
	}

	t.Run("all probes fail", func(t *testing.T) {
		check := runRound(t, 0, "failure")
		if check.Status != "failure" || check.PacketLossPercent != 100 {
			t.Errorf("status=%q loss=%f", check.Status, check.PacketLossPercent)
		}
	})
	t.Run("all probes succeed", func(t *testing.T) {
		check := runRound(t, pingProbeCount, "success")
		if check.Status != "success" || check.PacketLossPercent != 0 || check.ResponseTimeMs != 1.5 {
			t.Errorf("status=%q loss=%f rtt=%f", check.Status, check.PacketLossPercent, check.ResponseTimeMs)
		}
	})
	t.Run("partial success", func(t *testing.T) {
		check := runRound(t, 1, "success")
		if check.Status != "success" || check.PacketLossPercent <= 0 {
			t.Errorf("status=%q loss=%f", check.Status, check.PacketLossPercent)
		}
	})

	t.Run("already-finishing job returns without result", func(t *testing.T) {
		e, pj, _ := newTestPingJob(t, true)
		e.live[pj] = struct{}{}
		pj.finishing = true
		execPing = func(ctx context.Context, ip string, timeoutMs int) (float64, error) {
			return 1, nil
		}
		e.execPingRound(pj)
	})
}

func TestPingJobZeroProbeTimeout(t *testing.T) {
	orig := execPing
	t.Cleanup(func() { execPing = orig })
	e, pj, _ := newTestPingJob(t, true)
	e.live[pj] = struct{}{}
	pj.timeoutMs = 1 // 1/3 = 0 → clamped to 1
	got := make(chan int, 4)
	execPing = func(ctx context.Context, ip string, timeoutMs int) (float64, error) {
		got <- timeoutMs
		return 0, errors.New("x")
	}
	e.execPingRound(pj)
	select {
	case ms := <-got:
		if ms != 1 {
			t.Errorf("probeTimeoutMs = %d, want 1", ms)
		}
	case <-time.After(time.Second):
		t.Fatal("execPing not called")
	}
}

func TestHandleReplyPaths(t *testing.T) {
	e, pj, _ := newTestPingJob(t, false)
	e.live[pj] = struct{}{}
	waiter := &pingWaiter{}

	// Unknown waiter is ignored.
	e.handleReply(pingSocketEvent{w: waiter})

	// Reply for a finishing job is dropped after the index lookup.
	w2 := &pingWaiter{}
	e.waiterIndex[w2] = pingProbeRef{job: pj, prob: 0}
	pj.finishing = true
	e.handleReply(pingSocketEvent{w: w2})
	pj.finishing = false

	// Reply with an error records err and resolves the probe.
	sock := &icmpSocket{waiters: map[pingKey]*pingWaiter{}}
	w3 := &pingWaiter{}
	pj.probes[0].echo = sentEcho{sock: sock, key: pingKey{id: 1, seq: 1}}
	e.waiterIndex[w3] = pingProbeRef{job: pj, prob: 0}
	e.handleReply(pingSocketEvent{w: w3, reply: icmpReply{err: errors.New("unreachable")}})
	if pj.probes[0].err == nil || !pj.probes[0].checked || pj.resolved != 1 {
		t.Errorf("error reply: %+v resolved=%d", pj.probes[0], pj.resolved)
	}

	// Successful replies set RTT and finish the job after the last probe.
	for i := 1; i < pingProbeCount; i++ {
		pj.probes[i].echo = sentEcho{sock: sock, key: pingKey{id: 1, seq: i + 1}}
		pj.probes[i].start = time.Now().Add(-5 * time.Millisecond)
		w := &pingWaiter{}
		e.waiterIndex[w] = pingProbeRef{job: pj, prob: i}
		e.handleReply(pingSocketEvent{w: w, reply: icmpReply{received: time.Now()}})
	}
	if pj.replies != pingProbeCount-1 {
		t.Errorf("replies = %d, want %d", pj.replies, pingProbeCount-1)
	}
	if pj.firstRTT < 0 {
		t.Error("firstRTT must be recorded")
	}
	if !pj.finishing {
		t.Error("job must be finished after last probe")
	}
	if len(e.waiterIndex) != 0 {
		t.Errorf("waiter index leaked: %d", len(e.waiterIndex))
	}
}

func TestFinishJobLockedGuards(t *testing.T) {
	e, pj, _ := newTestPingJob(t, false)
	// finishing → early return.
	pj.finishing = true
	e.finishJobLocked(pj)
	// not live → early return.
	pj.finishing = false
	e.finishJobLocked(pj)
	if pj.finishing {
		t.Error("non-live job must stay unfinished")
	}

	// A live job with an outstanding waiter has it collected as a loss.
	e.live[pj] = struct{}{}
	sock := &icmpSocket{waiters: map[pingKey]*pingWaiter{}}
	w := &pingWaiter{}
	pj.probes[0].echo = sentEcho{sock: sock, key: pingKey{id: 9, seq: 9}}
	pj.probes[0].waiter = w
	e.waiterIndex[w] = pingProbeRef{job: pj, prob: 0}
	e.finishJobLocked(pj)
	if !pj.finishing || pj.resolved != 1 {
		t.Errorf("finish: finishing=%v resolved=%d", pj.finishing, pj.resolved)
	}
	if _, ok := e.waiterIndex[w]; ok {
		t.Error("waiter must be removed from the index")
	}
}

// Issue 5156: a ping round cancelled mid-flight measured nothing, so it
// must leave the previous reachability entry untouched instead of
// publishing "unreachable".
func TestCancelledPingRoundKeepsReachability(t *testing.T) {
	e, pj, _ := newTestPingJob(t, false)
	publishReachability("dev-1", nil, true, 7, 0)
	defer func() {
		reachabilityMu.Lock()
		delete(reachByDevice, "dev-1")
		reachabilityMu.Unlock()
	}()

	e.live[pj] = struct{}{}
	pj.cancel() // a reconnect or inventory replace cut the round short
	e.finishJobLocked(pj)

	entry, ok := lastDeviceReachability("dev-1")
	if !ok || !entry.reachable || entry.rttMs != 7 {
		t.Fatalf("cancelled round overwrote reachability: %+v %v", entry, ok)
	}
}

func TestSendProbeLockedPaths(t *testing.T) {
	// finishing → immediate return.
	e, pj, _ := newTestPingJob(t, false)
	pj.finishing = true
	e.sendProbeLocked(pj, 0)

	// startICMPPing failure marks the probe; three failures finish the job.
	pj.finishing = false
	e.live[pj] = struct{}{}
	pj.network = "no-such-network"
	done := make(chan struct{}, 1)
	pj.done = func() { done <- struct{}{} }
	for i := range pj.probes {
		e.sendProbeLocked(pj, i)
	}
	if pj.resolved != pingProbeCount {
		t.Errorf("resolved = %d, want %d", pj.resolved, pingProbeCount)
	}
	for i, p := range pj.probes {
		if p.err == nil {
			t.Errorf("probe %d must carry the dial error", i)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("done not called")
	}
}

func TestFireDueLocked(t *testing.T) {
	e, pj, _ := newTestPingJob(t, false)
	e.live[pj] = struct{}{}
	pj.network = "no-such-network" // sendProbeLocked errors fast
	now := time.Now()
	e.seq++
	heapPushPing(e, pingEvent{at: now.Add(-time.Second), seq: e.seq, job: pj, send: true, probe: 0})
	e.seq++
	heapPushPing(e, pingEvent{at: now.Add(-time.Second), seq: e.seq, job: pj, send: true, probe: 1})
	e.seq++
	heapPushPing(e, pingEvent{at: now.Add(-time.Second), seq: e.seq, job: pj, send: true, probe: 2})
	e.seq++
	heapPushPing(e, pingEvent{at: now.Add(-time.Second), seq: e.seq, job: pj, send: false})
	e.fireDueLocked()
	if !pj.finishing {
		t.Error("deadline event must finish the job")
	}
	if e.heap.Len() != 0 {
		t.Errorf("heap must be drained: %d", e.heap.Len())
	}
}

func heapPushPing(e *pingEngine, ev pingEvent) {
	e.heap = append(e.heap, ev)
	// Re-heapify via the container helper is unnecessary for a tiny test
	// heap; sort order only needs the earliest first for fireDueLocked.
}

func TestSubmitPingJobPaths(t *testing.T) {
	// Bad device → refusal returns false; done stays the caller's job.
	done := make(chan struct{}, 1)
	if submitPingJob(context.Background(), &pb.AgentJob{JobId: "bad"}, newResultQueue(4), func() { done <- struct{}{} }) {
		t.Error("job without device must fail")
	}
	select {
	case <-done:
		t.Error("refusal must not fire done")
	default:
	}

	// Full submit queue → false. A hand-built engine without goroutines
	// avoids the run loop draining the queue mid-fill.
	stopPingEngine()
	engine = newPingEngine(context.Background())
	engineOnce.Do(func() {}) // mark the once consumed so startPingEngine is a no-op
	t.Cleanup(func() {
		engine.cancel()
		engine = nil
		engineOnce = sync.Once{}
	})
	job := &pb.AgentJob{
		JobId:      "flood",
		SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1"},
	}
	for i := 0; i < cap(engine.submit); i++ {
		engine.submit <- &pingJob{ctx: context.Background(), cancel: func() {}}
	}
	done2 := make(chan struct{}, 1)
	if submitPingJob(context.Background(), job, newResultQueue(4), func() { done2 <- struct{}{} }) {
		t.Error("full queue must refuse")
	}
	select {
	case <-done2:
		t.Error("refusal must not fire done")
	default:
	}
	for i := 0; i < cap(engine.submit); i++ {
		<-engine.submit
	}
}

func TestPublishAndLookupReachability(t *testing.T) {
	publishReachability("dev-x", net.ParseIP("10.9.9.9"), true, 1.25, 0)
	entry, ok := lastDeviceReachability("dev-x")
	if !ok || !entry.reachable || entry.rttMs != 1.25 {
		t.Errorf("device reachability: %+v %v", entry, ok)
	}
	entry, ok = lastIPReachability("10.9.9.9")
	if !ok || !entry.reachable {
		t.Errorf("ip reachability: %+v %v", entry, ok)
	}
	if _, ok := lastDeviceReachability("missing"); ok {
		t.Error("missing device must miss")
	}
	if _, ok := lastIPReachability("10.9.9.8"); ok {
		t.Error("missing ip must miss")
	}
	// nil ip registers only by device.
	publishReachability("dev-nil", nil, false, 0, 100)
	if _, ok := lastDeviceReachability("dev-nil"); !ok {
		t.Error("nil ip device must register")
	}
}
