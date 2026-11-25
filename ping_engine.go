// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// pingProbeSpacingMs is the delay between consecutive echo probes in one
// ping round. Three probes spread over 400 ms sample short bursts of loss a
// single instant cannot see, while the round still completes inside the
// job's ping timeout.
const pingProbeSpacingMs = 200

// pingSubmitQueue bounds how many ping jobs wait for the engine's sender.
// 16384 covers the target fleet (3000 devices at 60 s intervals, plus a
// reconnect burst replaying the full inventory) with headroom; a full queue
// reports rejection to the scheduler instead of blocking it.
const pingSubmitQueue = 16384

// pingEventQueue bounds replies buffered between the shared socket's read
// loop and the engine's sender. The sender drains faster than replies
// arrive, so this only needs to absorb a burst.
const pingEventQueue = 4096

// pingFallbackQueue bounds jobs waiting for the exec-ping fallback workers.
// Overflow reports a rejection instead of dropping the job silently.
const pingFallbackQueue = 1024

// pingFallbackWorkers bounds concurrent exec-ping subprocesses. The fallback
// is an order of magnitude slower than the ICMP path even with one
// subprocess per device, so a small pool keeps a partial outage from
// starving healthy devices behind dead ones.
const pingFallbackWorkers = 16

// pingEngine replaces the ping worker pool: one goroutine sends echo
// requests from a time-ordered queue and the shared ICMP socket's read loop
// routes replies back, so no worker is held per ping. Jobs whose target has
// no usable ICMP socket fall back to one exec-ping worker.
//
// Integration: the scheduler routes pb.JobType_PING to submitPingJob instead
// of pools.ping. SNMP polls consult lastDeviceReachability to skip or
// shorten probes of devices that just answered or just went dark (A3).
type pingEngine struct {
	mu    sync.Mutex
	timer *time.Timer
	heap  pingEventHeap
	live  map[*pingJob]struct{}
	// waiterIndex maps a registered echo waiter to its owning job and probe
	// index, so a routed reply is O(1) to dispatch.
	waiterIndex map[*pingWaiter]pingProbeRef
	seq         uint64

	submit   chan *pingJob
	events   chan pingSocketEvent
	fallback chan *pingJob
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	// stopped is set under mu by shutdown; submitPingJob checks it under the
	// same mutex so a job can never land in submit after the drain ran.
	stopped bool
}

// pingProbeRef locates one probe inside a live job.
type pingProbeRef struct {
	job  *pingJob
	prob int
}

// pingJob is one device's ping round inside the engine.
type pingJob struct {
	ctx    context.Context
	cancel context.CancelFunc
	job    *pb.AgentJob
	out    *resultQueue
	done   func()

	ip        net.IP
	isIPv4    bool
	network   string
	needsExec bool

	timeoutMs int
	timestamp int64
	probes    []pingProbe
	replies   int
	resolved  int
	// localErrors counts probes that failed inside the agent (sendto,
	// marshal, exec): a round of only local errors measured nothing about
	// the device (issue 5162).
	localErrors int
	firstRTT    float64
	finishing   bool
}

// pingProbe is one echo request's state inside a job.
type pingProbe struct {
	echo    sentEcho
	start   time.Time
	waiter  *pingWaiter
	rttMs   float64
	err     error
	// localErr marks a failure inside the agent rather than silence from
	// the device (issue 5162).
	localErr bool
	sent     bool
	checked  bool
}

// deviceReachability is the per-device ping outcome the SNMP engine reads.
type deviceReachability struct {
	reachable bool
	rttMs     float64
	lossPct   float64
	at        time.Time
}

var (
	reachabilityMu sync.RWMutex
	reachByDevice  = make(map[string]deviceReachability)
	reachByIP      = make(map[string]deviceReachability)
)

func newPingEngine(ctx context.Context) *pingEngine {
	ctx, cancel := context.WithCancel(ctx)
	return &pingEngine{
		live:        make(map[*pingJob]struct{}),
		waiterIndex: make(map[*pingWaiter]pingProbeRef),
		submit:      make(chan *pingJob, pingSubmitQueue),
		events:      make(chan pingSocketEvent, pingEventQueue),
		fallback:    make(chan *pingJob, pingFallbackQueue),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// start launches the event loop and the exec fallback workers. The engine
// belongs to one poller: shutdown tears it down with the poller's pools.
func (e *pingEngine) start() {
	e.wg.Add(1 + pingFallbackWorkers)
	go e.run()
	for range pingFallbackWorkers {
		go e.runFallback()
	}
}

// shutdown cancels outstanding jobs, waits for the goroutines to return,
// then releases every job still queued on submit. run() is gone at that
// point, so nothing else can dequeue them and their done callbacks must
// still fire to free the target gates and unblock runTick waiters.
func (e *pingEngine) shutdown() {
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
	e.cancel()
	e.wg.Wait()
	for {
		select {
		case pj := <-e.submit:
			pj.cancel()
			if pj.done != nil {
				pj.done()
				pj.done = nil
			}
		default:
			return
		}
	}
}

// submitPingJob enqueues one ping round without holding a worker. Returns
// false when the queue is full or the engine is stopping; the caller owns
// done() in that case.
func submitPingJob(ctx context.Context, e *pingEngine, job *pb.AgentJob, out *resultQueue, done func()) bool {
	pj, ok := newPingJob(ctx, job, out, done)
	if !ok {
		// Refusal: the caller owns done and the target gate.
		return false
	}
	// The mutex orders the send against shutdown: once stopped is set the
	// engine never reads submit again, so a queued job would never finish.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		pj.cancel()
		return false
	}
	select {
	case e.submit <- pj:
		return true
	default:
		// Refusal: the caller owns done and the target gate. Calling done
		// here as well would release the gate twice and wedge the worker on
		// a drained semaphore.
		pj.cancel()
		recordJobDropped()
		return false
	}
}

// newPingJob resolves the target and picks the transport once, so the
// sender's hot path only writes and waits.
func newPingJob(ctx context.Context, job *pb.AgentJob, out *resultQueue, done func()) (*pingJob, bool) {
	dev := job.SnmpDevice
	if dev == nil || net.ParseIP(dev.Ip) == nil {
		return nil, false
	}
	ip := net.ParseIP(dev.Ip)
	isIPv4 := ip.To4() != nil
	network, needsExec := selectPingNetwork(isIPv4)

	timeoutMs := int(job.PingTimeoutMs)
	if timeoutMs <= 0 {
		timeoutMs = defaultPingTimeoutMs
	}

	jobCtx, cancel := context.WithCancel(ctx)
	now := time.Now()
	pj := &pingJob{
		ctx:       jobCtx,
		cancel:    cancel,
		job:       job,
		out:       out,
		done:      done,
		ip:        ip,
		isIPv4:    isIPv4,
		network:   network,
		needsExec: needsExec,
		timeoutMs: timeoutMs,
		timestamp: now.Unix(),
		probes:    make([]pingProbe, pingProbeCount),
	}
	return pj, true
}

// selectPingNetwork picks the ICMP network the shared socket should use, or
// reports that the exec fallback is needed. A listen failure on the raw
// socket falls through to the unprivileged UDP socket; if both fail the job
// uses exec ping, preserving the existing fallback chain.
func selectPingNetwork(isIPv4 bool) (string, bool) {
	rawNet, udpNet := "ip4:icmp", "udp4"
	if !isIPv4 {
		rawNet, udpNet = "ip6:ipv6-icmp", "udp6"
	}
	if s, err := sharedSocket(rawNet); err == nil {
		_ = s
		return rawNet, false
	}
	if s, err := sharedSocket(udpNet); err == nil {
		_ = s
		return udpNet, false
	}
	return "", true
}

// pingEvent is one scheduled action: send probe i, or expire probe i when
// its own reply window closes.
type pingEvent struct {
	at    time.Time
	seq   uint64
	job   *pingJob
	send  bool // true = send probe; false = probe reply window expired
	probe int
}

// pingEventHeap is a min-heap of pingEvents ordered by time.
type pingEventHeap []pingEvent

func (h pingEventHeap) Len() int            { return len(h) }
func (h pingEventHeap) Less(i, j int) bool  { return h[i].at.Before(h[j].at) }
func (h pingEventHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *pingEventHeap) Push(x interface{}) { *h = append(*h, x.(pingEvent)) }
func (h *pingEventHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (e *pingEngine) run() {
	defer e.wg.Done()
	defer e.drainLive()

	for {
		select {
		case <-e.ctx.Done():
			return

		case pj := <-e.submit:
			e.enqueueJob(pj)

		case ev := <-e.events:
			e.handleReply(ev)
		}
	}
}

// enqueueJob schedules the probe sends and their expiries for one job, or
// hands an exec-fallback job straight to the fallback worker.
func (e *pingEngine) enqueueJob(pj *pingJob) {
	if pj.ctx.Err() != nil {
		pj.cancel()
		pj.done()
		return
	}
	if pj.needsExec {
		pj.noteExecFallback()
		e.mu.Lock()
		e.live[pj] = struct{}{}
		e.mu.Unlock()
		select {
		case e.fallback <- pj:
		default:
			e.mu.Lock()
			delete(e.live, pj)
			pj.finishing = true
			recordJobDropped()
			// The overflow used to drop the job silently; the server
			// needs the same busy signal a pool refusal would send.
			sendResult(pj.ctx, pj.out, "error", &pb.AgentError{
				DeviceId:  pj.job.DeviceId,
				JobId:     pj.job.JobId,
				Message:   "ping check could not run on the agent: exec fallback queue full",
				Timestamp: time.Now().Unix(),
			}, pj.job.JobId)
			pj.cancel()
			pj.done()
			e.mu.Unlock()
		}
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.live[pj] = struct{}{}
	now := time.Now()
	timeout := time.Duration(pj.timeoutMs) * time.Millisecond
	for i := range pj.probes {
		// Each probe gets the full timeout measured from its own send. One
		// shared round deadline would shorten the later probes' windows and
		// skip them entirely under about a second, so a healthy device
		// reported steady loss at low timeouts (issue 5161).
		at := now.Add(time.Duration(i*pingProbeSpacingMs) * time.Millisecond)
		e.seq++
		heap.Push(&e.heap, pingEvent{at: at, seq: e.seq, job: pj, send: true, probe: i})
		e.seq++
		heap.Push(&e.heap, pingEvent{at: at.Add(timeout), seq: e.seq, job: pj, send: false, probe: i})
	}
	e.resetTimerLocked()
}

// resetTimerLocked re-arms the send timer from the heap's earliest event.
// Called with e.mu held.
func (e *pingEngine) resetTimerLocked() {
	if e.timer != nil {
		e.timer.Stop()
	}
	if e.heap.Len() == 0 {
		e.timer = nil
		return
	}
	delay := time.Until(e.heap[0].at)
	if delay < 0 {
		delay = 0
	}
	e.timer = time.AfterFunc(delay, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.fireDueLocked()
	})
}

// fireDueLocked pops and processes every event whose time has come.
// Called with e.mu held.
func (e *pingEngine) fireDueLocked() {
	now := time.Now()
	for e.heap.Len() > 0 && !e.heap[0].at.After(now) {
		ev := heap.Pop(&e.heap).(pingEvent)
		if _, live := e.live[ev.job]; !live {
			continue
		}
		if ev.send {
			e.sendProbeLocked(ev.job, ev.probe)
		} else {
			e.expireProbeLocked(ev.job, ev.probe)
		}
	}
	e.resetTimerLocked()
}

// sendProbeLocked writes one echo request on the shared socket. Called with
// e.mu held; the WriteTo syscall is the only blocking call and returns in
// microseconds for a local send.
func (e *pingEngine) sendProbeLocked(pj *pingJob, idx int) {
	if pj.finishing {
		return
	}
	echo, start, err := startICMPPing(pj.ctx, pj.ip, pj.network, pj.isIPv4, e.events)
	if err != nil {
		pj.probes[idx].err = err
		if pj.ctx.Err() == nil {
			// A live context means the echo never left the agent: the
			// device was not probed at all (issue 5162).
			pj.probes[idx].localErr = true
			pj.localErrors++
		}
		pj.probes[idx].checked = true
		pj.resolved++
		if pj.resolved == pingProbeCount {
			e.finishJobLocked(pj)
			e.resetTimerLocked()
		}
		return
	}
	pj.probes[idx].echo = echo
	pj.probes[idx].start = start
	pj.probes[idx].waiter = echo.w
	pj.probes[idx].sent = true
	e.waiterIndex[echo.w] = pingProbeRef{job: pj, prob: idx}
}

// expireProbeLocked resolves one probe whose own reply window closed
// without an answer: it counts as loss. Called with e.mu held.
func (e *pingEngine) expireProbeLocked(pj *pingJob, idx int) {
	if pj.finishing {
		return
	}
	p := &pj.probes[idx]
	if p.checked {
		return
	}
	if p.waiter != nil {
		p.echo.sock.unregister(p.echo.key, p.waiter)
		delete(e.waiterIndex, p.waiter)
		p.waiter = nil
	}
	p.checked = true
	pj.resolved++
	if pj.resolved == pingProbeCount {
		e.finishJobLocked(pj)
		e.resetTimerLocked()
	}
}

// handleReply routes one reply from the shared socket to its probe.
func (e *pingEngine) handleReply(ev pingSocketEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ref, ok := e.waiterIndex[ev.w]
	if !ok {
		return
	}
	delete(e.waiterIndex, ev.w)
	pj, idx := ref.job, ref.prob
	if pj.finishing {
		return
	}
	p := &pj.probes[idx]
	p.echo.sock.unregister(p.echo.key, p.echo.w)
	p.waiter = nil
	p.checked = true
	pj.resolved++
	if ev.reply.err != nil {
		p.err = ev.reply.err
	} else {
		rtt := float64(ev.reply.received.Sub(p.start).Microseconds()) / 1000.0
		p.rttMs = rtt
		pj.replies++
		if pj.replies == 1 {
			pj.firstRTT = rtt
		}
	}
	if pj.resolved == pingProbeCount {
		e.finishJobLocked(pj)
		e.resetTimerLocked()
	}
}

// finishJobLocked collects outstanding probes as losses and sends the result.
// Called with e.mu held.
func (e *pingEngine) finishJobLocked(pj *pingJob) {
	if pj.finishing {
		return
	}
	if _, live := e.live[pj]; !live {
		return
	}
	delete(e.live, pj)
	pj.finishing = true

	for idx := range pj.probes {
		p := &pj.probes[idx]
		if p.waiter != nil {
			p.echo.sock.unregister(p.echo.key, p.echo.w)
			delete(e.waiterIndex, p.waiter)
			p.waiter = nil
			p.checked = true
			pj.resolved++
		}
		p.checked = true
	}

	lossPercent := float64(pingProbeCount-pj.replies) * 100.0 / float64(pingProbeCount)
	status := "success"
	if pj.replies == 0 {
		status = "failure"
	}
	result := &pb.MonitoringCheck{
		DeviceId:          pj.job.DeviceId,
		Status:            status,
		Timestamp:         pj.timestamp,
		PacketLossPercent: lossPercent,
	}
	if pj.replies > 0 {
		result.ResponseTimeMs = pj.firstRTT
	}

	switch pj.replies {
	case pingProbeCount:
		recordJobRun()
	case 0:
		recordJobFailure()
	default:
		recordJobRun()
		recordJobPartial()
	}

	if pj.ctx.Err() == nil {
		if pj.allLocalErrors() {
			// Every probe failed inside the agent: publish no
			// "unreachable" hint and report the agent fault instead of a
			// down device (issue 5162).
			pj.reportLocalPingFailure()
		} else {
			// A round cut short by a reconnect or inventory replace measured
			// nothing: it must not publish an "unreachable" hint (issue 5156).
			publishReachability(pj.job.DeviceId, pj.ip, pj.replies > 0, pj.firstRTT, lossPercent)
			slog.Debug("ping job complete", "device", pj.job.DeviceId, "status", status,
				"replies", pj.replies, "probes", pingProbeCount, "loss_percent", lossPercent)
			sendResult(pj.ctx, pj.out, "monitoring_check", result, pj.job.JobId)
		}
	}
	// Cancel only after the completed measurement has entered the spool.
	pj.cancel()
	if pj.done != nil {
		pj.done()
		pj.done = nil
	}
}

// allLocalErrors reports whether every probe of the round failed inside
// the agent itself, so the result says nothing about the device.
func (pj *pingJob) allLocalErrors() bool {
	return pj.replies == 0 && pj.localErrors == pingProbeCount
}

// firstLocalError returns the first agent-side probe error for reporting.
func (pj *pingJob) firstLocalError() error {
	for i := range pj.probes {
		if pj.probes[i].localErr {
			return pj.probes[i].err
		}
	}
	return nil
}

// reportLocalPingFailure sends an agent error for a round whose probes
// never left the agent: a sendto refusal, marshal failure or unusable exec
// binary is host-local, so the device is reported unmeasured, not down
// (issue 5162).
func (pj *pingJob) reportLocalPingFailure() {
	processMetrics.pingLocalErrors.Add(1)
	err := pj.firstLocalError()
	slog.Error("ping round could not send any probe",
		"device", pj.job.DeviceId, "ip", pj.ip, "error", err)
	sendResult(pj.ctx, pj.out, "error", &pb.AgentError{
		DeviceId:  pj.job.DeviceId,
		JobId:     pj.job.JobId,
		Message:   fmt.Sprintf("ping check could not run on the agent: %v", err),
		Timestamp: time.Now().Unix(),
	}, pj.job.JobId)
}

// drainLive cancels every outstanding job at shutdown without sending results.
func (e *pingEngine) drainLive() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for pj := range e.live {
		delete(e.live, pj)
		pj.finishing = true
		pj.cancel()
		if pj.done != nil {
			pj.done()
			pj.done = nil
		}
	}
}

// noteExecFallback reports once that the host cannot open any ICMP socket
// and pings will run through the system binary. The mode is an order of
// magnitude slower, so it is visible on the debug metrics as
// ping_exec_fallback 1 until the agent restarts.
func (pj *pingJob) noteExecFallback() {
	if processMetrics.pingExecFallback.CompareAndSwap(0, 1) {
		slog.Warn("no ICMP socket available; ping checks run through the exec fallback, which is much slower")
	}
}

// runFallback processes jobs whose target has no usable ICMP socket. One of
// pingFallbackWorkers goroutines runs one `ping -c N` subprocess per device.
func (e *pingEngine) runFallback() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case pj := <-e.fallback:
			e.execPingRound(pj)
		}
	}
}

// execPingRound runs the three-probe round through the system ping binary.
// The engine's mutex is NOT held during the subprocess calls so ICMP jobs
// keep flowing; the fallback worker is this job's only writer after enqueue.
func (e *pingEngine) execPingRound(pj *pingJob) {
	if pj.ctx.Err() != nil {
		e.mu.Lock()
		delete(e.live, pj)
		pj.finishing = true
		pj.cancel()
		if pj.done != nil {
			pj.done()
			pj.done = nil
		}
		e.mu.Unlock()
		return
	}
	// One subprocess sends all probes at the same 200 ms spacing the ICMP
	// engine uses. The job context bounds the whole round, so a round can
	// never outlive the configured timeout the way sequential per-probe
	// waits could.
	replies, firstRTT, err := execPingSeries(pj.ctx, pj.job.SnmpDevice.Ip, pingProbeCount, pj.timeoutMs)
	if err == nil {
		pj.replies = replies
		pj.firstRTT = firstRTT
	}
	localErr := err != nil && pj.ctx.Err() == nil && pingIsLocalExecError(err)
	for i := range pj.probes {
		pj.probes[i].err = err
		if localErr {
			pj.probes[i].localErr = true
			pj.localErrors++
		}
		pj.probes[i].checked = true
		pj.resolved++
	}

	e.mu.Lock()
	if pj.finishing {
		// drainLive already cancelled this job during engine shutdown.
		e.mu.Unlock()
		return
	}
	delete(e.live, pj)
	pj.finishing = true

	// Send BEFORE cancel: pj.ctx.Err() gates the send, so cancelling here
	// would silently drop every exec-fallback result.

	lossPercent := float64(pingProbeCount-pj.replies) * 100.0 / float64(pingProbeCount)
	status := "success"
	if pj.replies == 0 {
		status = "failure"
	}
	result := &pb.MonitoringCheck{
		DeviceId:          pj.job.DeviceId,
		Status:            status,
		Timestamp:         pj.timestamp,
		PacketLossPercent: lossPercent,
	}
	if pj.replies > 0 {
		result.ResponseTimeMs = pj.firstRTT
	}

	switch pj.replies {
	case pingProbeCount:
		recordJobRun()
	case 0:
		recordJobFailure()
	default:
		recordJobRun()
		recordJobPartial()
	}

	if pj.ctx.Err() == nil {
		if pj.allLocalErrors() {
			pj.reportLocalPingFailure()
		} else {
			// A round cut short by a reconnect or inventory replace measured
			// nothing: it must not publish an "unreachable" hint (issue 5156).
			publishReachability(pj.job.DeviceId, pj.ip, pj.replies > 0, pj.firstRTT, lossPercent)
			slog.Debug("ping job complete", "device", pj.job.DeviceId, "status", status,
				"replies", pj.replies, "probes", pingProbeCount, "loss_percent", lossPercent)
			sendResult(pj.ctx, pj.out, "monitoring_check", result, pj.job.JobId)
		}
	}
	// Cancel only after the completed measurement has entered the spool.
	pj.cancel()
	if pj.done != nil {
		pj.done()
		pj.done = nil
	}
	e.mu.Unlock()
}

// pingIsLocalExecError classifies an exec-fallback probe failure. A binary
// that cannot be started, or that exits for a reason other than "no reply"
// (exit status 1), is an agent-side fault rather than evidence the device
// is down (issue 5162). Timeouts and plain no-reply exits stay device loss.
func pingIsLocalExecError(err error) bool {
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode() != 1
	}
	return false
}

// publishReachability records a ping round's outcome for the SNMP engine.
func publishReachability(deviceID string, ip net.IP, reachable bool, rttMs, lossPct float64) {
	entry := deviceReachability{
		reachable: reachable,
		rttMs:     rttMs,
		lossPct:   lossPct,
		at:        time.Now(),
	}
	reachabilityMu.Lock()
	reachByDevice[deviceID] = entry
	if ip != nil {
		reachByIP[ip.String()] = entry
	}
	reachabilityMu.Unlock()
}

// lastDeviceReachability returns the device's most recent ping outcome.
func lastDeviceReachability(deviceID string) (deviceReachability, bool) {
	reachabilityMu.RLock()
	defer reachabilityMu.RUnlock()
	entry, ok := reachByDevice[deviceID]
	return entry, ok
}

// lastIPReachability returns the most recent ping outcome for an IP address.
func lastIPReachability(ip string) (deviceReachability, bool) {
	reachabilityMu.RLock()
	defer reachabilityMu.RUnlock()
	entry, ok := reachByIP[ip]
	return entry, ok
}
