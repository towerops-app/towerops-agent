// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// agentMetrics holds the process-wide runtime counters reported on the
// heartbeat and exposed by --debug-listen. Engines record into it instead of
// keeping parallel private counters, so one snapshot covers every pool and
// protocol.
type agentMetrics struct {
	snmpTimeouts    atomic.Uint64
	rateLimitWaitNs atomic.Uint64
	skippedTicks    atomic.Uint64
	scheduleLagMu   sync.Mutex
	scheduleLag     []uint64
	scheduleLagPos  int
	scheduleLagFull bool
}

var processMetrics = &agentMetrics{}

// resultQueueDroppedTotal accumulates spool drops across spool instances. The
// per-instance queue reports the same value through its own dropped counter.
var resultQueueDroppedTotal atomic.Uint64

// scheduleLagCapacity keeps a bounded recent-window sample set. A p95 over the
// last few thousand ticks is stable enough for capacity alerting without
// retaining an unbounded histogram.
const scheduleLagCapacity = 2048

func (m *agentMetrics) recordScheduleLag(lag time.Duration) {
	if lag < 0 {
		lag = 0
	}
	ms := uint64(lag.Milliseconds())
	m.scheduleLagMu.Lock()
	if len(m.scheduleLag) < scheduleLagCapacity {
		m.scheduleLag = append(m.scheduleLag, ms)
	} else {
		m.scheduleLag[m.scheduleLagPos] = ms
		m.scheduleLagPos = (m.scheduleLagPos + 1) % scheduleLagCapacity
		m.scheduleLagFull = true
	}
	m.scheduleLagMu.Unlock()
}

// scheduleLagP95 returns the 95th percentile over the retained sample window
// in milliseconds, and whether any sample exists.
func (m *agentMetrics) scheduleLagP95() (uint64, bool) {
	m.scheduleLagMu.Lock()
	samples := make([]uint64, len(m.scheduleLag))
	copy(samples, m.scheduleLag)
	m.scheduleLagMu.Unlock()
	if len(samples) == 0 {
		return 0, false
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	index := len(samples) * 95 / 100
	if index >= len(samples) {
		index = len(samples) - 1
	}
	return samples[index], true
}

// metricsSnapshot is a consistent point-in-time copy of the engine counters.
type metricsSnapshot struct {
	SNMPTimeouts      uint64
	RateLimitWaitMS   uint64
	SkippedTicks      uint64
	ScheduleLagMS     uint64
	HasScheduleLag    bool
	ResultDropped     uint64
	TrapsDropped      uint64
	SpoolDepth        uint64
	SpoolBytes        uint64
	SpoolLimit        uint64
	Pools             []poolLoadSnapshot
	InventoryCapacity uint64
}

type poolLoadSnapshot struct {
	Name   string
	Busy   uint64
	Queued uint64
}

// poolLoadSnapshotHook is installed by the process poller once worker pools
// exist. The debug listener reads through it so diagnostics survive reconnects.
var poolLoadSnapshotHook atomic.Pointer[func() []poolLoadSnapshot]

func poolLoadSnapshots() []poolLoadSnapshot {
	if hook := poolLoadSnapshotHook.Load(); hook != nil && *hook != nil {
		return (*hook)()
	}
	return nil
}

func (m *agentMetrics) snapshot() metricsSnapshot {
	lag, hasLag := m.scheduleLagP95()
	return metricsSnapshot{
		SNMPTimeouts:    m.snmpTimeouts.Load(),
		RateLimitWaitMS: m.rateLimitWaitNs.Load() / uint64(time.Millisecond),
		SkippedTicks:    m.skippedTicks.Load(),
		ScheduleLagMS:   lag,
		HasScheduleLag:  hasLag,
		ResultDropped:   resultQueueDroppedTotal.Load(),
		TrapsDropped:    trapDroppedTotal.Load(),
	}
}

func formatMetrics(snapshot metricsSnapshot, poolLoads []poolLoadSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "snmp_timeouts %d\n", snapshot.SNMPTimeouts)
	fmt.Fprintf(&b, "rate_limit_wait_ms %d\n", snapshot.RateLimitWaitMS)
	fmt.Fprintf(&b, "skipped_ticks %d\n", snapshot.SkippedTicks)
	fmt.Fprintf(&b, "schedule_lag_ms_p95 %d\n", snapshot.ScheduleLagMS)
	fmt.Fprintf(&b, "results_dropped %d\n", snapshot.ResultDropped)
	fmt.Fprintf(&b, "traps_dropped %d\n", snapshot.TrapsDropped)
	fmt.Fprintf(&b, "spool_depth %d\n", snapshot.SpoolDepth)
	fmt.Fprintf(&b, "spool_bytes %d\n", snapshot.SpoolBytes)
	if snapshot.InventoryCapacity > 0 {
		fmt.Fprintf(&b, "inventory_capacity_devices %d\n", snapshot.InventoryCapacity)
	}
	for _, pool := range poolLoads {
		fmt.Fprintf(&b, "pool_busy{name=%q} %d\n", pool.Name, pool.Busy)
		fmt.Fprintf(&b, "pool_queued{name=%q} %d\n", pool.Name, pool.Queued)
	}
	return b.String()
}

// isLoopbackListenAddress accepts only loopback listeners. A misconfigured
// address must fail startup rather than expose profiles and runtime metrics to
// the network.
func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// startDebugServer serves pprof profiles and the text metrics page on loopback.
// The returned closer stops the listener; an idle timeout bounds stuck requests.
func startDebugServer(address string, loadsFn func() []poolLoadSnapshot) (func(), error) {
	if !isLoopbackListenAddress(address) {
		return nil, fmt.Errorf("debug listen address must be loopback host:port, got %q", address)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	for _, profile := range []string{
		"allocs", "block", "goroutine", "heap", "mutex", "threadcreate",
	} {
		mux.Handle("/debug/pprof/"+profile, pprof.Handler(profile))
	}
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var loads []poolLoadSnapshot
		if loadsFn != nil {
			loads = loadsFn()
		}
		_, _ = w.Write([]byte(formatMetrics(processMetrics.snapshot(), loads)))
	})
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("debug listener %s: %w", address, err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	return func() {
		_ = server.Close()
		<-done
	}, nil
}
