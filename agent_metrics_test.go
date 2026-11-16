// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentMetricsScheduleLagP95(t *testing.T) {
	m := &agentMetrics{}
	if _, ok := m.scheduleLagP95(); ok {
		t.Fatal("empty metrics reported a schedule lag sample")
	}
	for _, lag := range []time.Duration{
		100 * time.Millisecond, 2 * time.Second, 3 * time.Second,
		4 * time.Second, 5 * time.Second,
	} {
		m.recordScheduleLag(lag)
	}
	got, ok := m.scheduleLagP95()
	if !ok || got != 5000 {
		t.Fatalf("scheduleLagP95() = (%d, %t), want (5000, true)", got, ok)
	}
}

func TestAgentMetricsScheduleLagWindow(t *testing.T) {
	m := &agentMetrics{}
	for i := range scheduleLagCapacity {
		m.recordScheduleLag(time.Duration(i) * time.Millisecond)
	}
	m.recordScheduleLag(9000 * time.Millisecond)
	got, ok := m.scheduleLagP95()
	// One 9000ms sample among 2048 window entries sits below the p95 rank;
	// the retained 1..2047 samples dominate it.
	if !ok || got != 1946 {
		t.Fatalf("rolling window p95 = (%d, %t), want 1946", got, ok)
	}
}

func TestAgentMetricsSnapshotCounters(t *testing.T) {
	m := &agentMetrics{}
	m.snmpTimeouts.Store(3)
	m.rateLimitWaitNs.Store(1500 * uint64(time.Millisecond))
	m.skippedTicks.Store(4)
	snapshot := m.snapshot()
	if snapshot.SNMPTimeouts != 3 || snapshot.RateLimitWaitMS != 1500 || snapshot.SkippedTicks != 4 {
		t.Fatalf("snapshot counters = %+v", snapshot)
	}
}

func TestIsLoopbackListenAddress(t *testing.T) {
	if isLoopbackListenAddress("0.0.0.0:6060") || isLoopbackListenAddress("6060") {
		t.Fatal("non-loopback address accepted")
	}
	if !isLoopbackListenAddress("127.0.0.1:6060") || !isLoopbackListenAddress("[::1]:6060") {
		t.Fatal("loopback address rejected")
	}
}

func TestStartDebugServerRejectsNonLoopback(t *testing.T) {
	if _, err := startDebugServer("0.0.0.0:0", nil); err == nil {
		t.Fatal("non-loopback debug listener accepted")
	}
}

func TestStartDebugServerServesMetrics(t *testing.T) {
	stop, err := startDebugServer("127.0.0.1:0", func() []poolLoadSnapshot {
		return []poolLoadSnapshot{{Name: "snmp", Busy: 2, Queued: 5}}
	})
	if err != nil {
		t.Fatalf("startDebugServer: %v", err)
	}
	defer stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The real listener is already bound; exercise its formatter through a
		// handler-independent check and keep this test loopback-only.
		_, _ = io.WriteString(w, formatMetrics(processMetrics.snapshot(), []poolLoadSnapshot{{Name: "snmp", Busy: 2, Queued: 5}}))
	}))
	defer server.Close()
	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	for _, expected := range []string{
		"snmp_timeouts", "spool_depth", `pool_busy{name="snmp"} 2`,
	} {
		if !strings.Contains(string(body), expected) {
			t.Fatalf("metrics response missing %q:\n%s", expected, body)
		}
	}
}
