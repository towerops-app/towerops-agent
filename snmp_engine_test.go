// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func TestSnmpOIDLessNumericArcsAllocFree(t *testing.T) {
	if !snmpOIDLess("1.3.6.1.2.9", "1.3.6.1.2.10") {
		t.Fatal("arcs must compare numerically, not lexicographically")
	}
	if snmpOIDLess("1.3.6.1.2.10", "1.3.6.1.2.9") {
		t.Fatal("comparison is not antisymmetric for numeric arcs")
	}
	if !snmpOIDLess("1.3.6.1", "1.3.6.1.0") {
		t.Fatal("a shorter OID must sort before its extension")
	}
	if snmpOIDLess("1.3.6.1", "1.3.6.1") {
		t.Fatal("equal OIDs must not compare less")
	}
	if !snmpOIDLess(".1.3.6.1", "1.3.6.1.0") {
		t.Fatal("a leading dot must not change the comparison")
	}
	allocs := testing.AllocsPerRun(200, func() {
		_ = snmpOIDLess("1.3.6.1.2.1.2.2.1.10.1", "1.3.6.1.2.1.2.2.1.10.2")
	})
	if allocs != 0 {
		t.Fatalf("snmpOIDLess made %v allocations, want zero on the walk hot path", allocs)
	}
}

// A3: one zero-response GET aborts the poll and puts the device into silent
// health; the next tick asks only sysUpTime.0 until it answers.
func TestExecuteSnmpJobSilentHealthLifecycle(t *testing.T) {
	const deviceID = "silent-lifecycle-device"
	origDial := snmpDial
	t.Cleanup(func() { snmpDial = origDial })

	calls := 0
	var oids []string
	snmpDial = func(_ context.Context, job *pb.AgentJob) (snmpQuerier, func(), error) {
		calls++
		return &mockSnmpQuerier{
			getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
				oids = append(oids, batch...)
				if len(batch) == 1 && batch[0] == oidSNMPsysUpTime {
					return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
						{Name: "." + oidSNMPsysUpTime, Type: gosnmp.TimeTicks, Value: uint32(1)},
					}}, nil
				}
				if calls == 1 {
					return nil, errors.New("request timeout: no response")
				}
				return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
					{Name: "." + batch[0], Type: gosnmp.OctetString, Value: []byte("up")},
				}}, nil
			},
		}, func() {}, nil
	}

	state := defaultSNMPEngine.state(&pb.AgentJob{DeviceId: deviceID})
	t.Cleanup(func() { resetSNMPDeviceState(&pb.AgentJob{DeviceId: deviceID}) })

	out := newResultQueue(4)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "silent-first",
		DeviceId:   deviceID,
		SnmpDevice: &pb.SnmpDevice{Ip: "192.0.2.1"},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}},
		},
	}, out)
	if !state.isSilent() {
		t.Fatal("a first-tick timeout did not mark the device silent")
	}
	result := decodeQueuedResult[*pb.SnmpResult](t, <-out.items)
	if !result.Partial || len(result.OidValues) != 0 {
		t.Fatalf("aborted result = %+v, want an empty partial result", result)
	}
	notice := decodeQueuedResult[*pb.AgentError](t, <-out.items)
	if !strings.Contains(notice.Message, "GET: request timeout") {
		t.Fatalf("abort notice = %q", notice.Message)
	}

	oids = nil
	calls = 0
	out = newResultQueue(2)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "silent-recovery",
		DeviceId:   deviceID,
		SnmpDevice: &pb.SnmpDevice{Ip: "192.0.2.1"},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: []string{"1.3.6.1.2.1.1.1.0"}},
		},
	}, out)
	if calls != 2 {
		t.Fatalf("silent recovery dialed %d times, want one probe dial plus one poll dial", calls)
	}
	if len(oids) != 2 || oids[0] != oidSNMPsysUpTime || oids[1] != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("silent recovery requested %v, want sysUpTime first and then the poll OID", oids)
	}
	if state.isSilent() {
		t.Fatal("a successful health probe did not clear silent health")
	}
	result = decodeQueuedResult[*pb.SnmpResult](t, <-out.items)
	if !result.Final || result.Partial {
		t.Fatalf("recovered result = %+v, want a final result", result)
	}
}

// The ping reachability hint suppresses only the silent-device probe. An
// ICMP-filtered device with no silent history must keep polling SNMP.
func TestSNMPPingHintSkipsSilentProbeOnly(t *testing.T) {
	const deviceID = "ping-hint-device"
	const ip = "192.0.2.77"
	origDial := snmpDial
	t.Cleanup(func() {
		snmpDial = origDial
		publishReachability(deviceID, net.ParseIP(ip), true, 0, 0)
	})
	publishReachability(deviceID, net.ParseIP(ip), false, 0, 0)

	state := defaultSNMPEngine.state(&pb.AgentJob{DeviceId: deviceID})
	t.Cleanup(func() { resetSNMPDeviceState(&pb.AgentJob{DeviceId: deviceID}) })
	state.markSilent(false)

	dialed := false
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		dialed = true
		return &mockSnmpQuerier{}, func() {}, nil
	}
	out := newResultQueue(1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "ping-skip",
		DeviceId:   deviceID,
		SnmpDevice: &pb.SnmpDevice{Ip: ip},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: []string{"1.3.6.1.2.1.1.1.0"}},
		},
	}, out)
	if dialed {
		t.Fatal("an unreachable ping hint did not suppress the silent-device probe")
	}
	result := decodeQueuedResult[*pb.SnmpResult](t, <-out.items)
	if !result.Partial || len(result.OidValues) != 0 {
		t.Fatalf("skipped result = %+v, want an empty partial result", result)
	}

	publishReachability(deviceID, net.ParseIP(ip), true, 0, 0)
	state.markSilent(false)
	out = newResultQueue(1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "ping-recovers-probe",
		DeviceId:   deviceID,
		SnmpDevice: &pb.SnmpDevice{Ip: ip},
	}, out)
	if !dialed {
		t.Fatal("a reachable ping hint wrongly suppressed the silent-device probe")
	}
	if result := decodeQueuedResult[*pb.SnmpResult](t, <-out.items); !result.Final {
		t.Fatalf("healthy probe result = %+v", result)
	}
}

// B5: after any earlier response, a timed-out GET batch is retried in halves
// and the working half size is remembered for the next tick.
func TestSnmpGetRecoveryHalvesTimedOutBatch(t *testing.T) {
	state := newSNMPDeviceState(defaultSNMPDevicePDURate)
	var sizes []int
	mock := &mockSnmpQuerier{
		getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
			sizes = append(sizes, len(batch))
			if len(batch) == 4 {
				return nil, errors.New("read timeout")
			}
			vars := make([]gosnmp.SnmpPDU, len(batch))
			for i, oid := range batch {
				vars[i] = gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.Integer, Value: int64(i + 1)}
			}
			return &gosnmp.SnmpPacket{Variables: vars}, nil
		},
	}
	conn := &snmpJobQuerier{
		q:           mock,
		state:       state,
		observation: &snmpObservation{responded: true},
	}
	oids := []string{"1.3.6.1.4.1.9.1", "1.3.6.1.4.1.9.2", "1.3.6.1.4.1.9.3", "1.3.6.1.4.1.9.4"}
	values := make(map[string]string)
	absent, err := snmpGetWithRecovery(context.Background(), conn, &pb.SnmpDevice{Ip: "192.0.2.9"}, state, oids, values)
	if err != nil || absent != 0 || len(values) != 4 {
		t.Fatalf("recovery = absent %d, err %v, values %d", absent, err, len(values))
	}
	if fmt.Sprint(sizes) != "[4 2 2]" {
		t.Fatalf("GET batch sizes = %v, want one timeout followed by two halves", sizes)
	}
	if got := state.getSize(); got != 2 {
		t.Fatalf("remembered GET size = %d, want the working half size 2", got)
	}
}

// B2: a device keeps one session across ticks and credential replacement
// evicts the old socket instead of leaking it.
func TestSNMPDeviceSessionCacheReplacement(t *testing.T) {
	port := snwTFreeUDPPort(t)
	job := &pb.AgentJob{
		DeviceId:   "session-cache-device",
		SnmpDevice: &pb.SnmpDevice{Ip: "127.0.0.1", Port: uint32(port), Version: "2c", Community: "first"},
	}
	state := defaultSNMPEngine.state(job)
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	first, firstClose, err := state.dial(context.Background(), job)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	firstLimited, ok := first.(*rateLimitedQuerier)
	if !ok || firstLimited.q == nil {
		t.Fatalf("first querier = %T", first)
	}
	firstConn := firstLimited.q.(*gosnmp.GoSNMP)
	firstClose()

	// Idle expiry replaces the cached socket even without a credential change.
	state.session.lastUsed = time.Now().Add(-snmpSessionIdleTimeout)
	idleReplacement, idleClose, err := state.dial(context.Background(), job)
	if err != nil {
		t.Fatalf("idle replacement dial: %v", err)
	}
	idleConn := idleReplacement.(*rateLimitedQuerier).q.(*gosnmp.GoSNMP)
	if idleConn == firstConn {
		t.Fatal("idle-expired session was reused")
	}
	if _, err := firstConn.Conn.Write([]byte("x")); err == nil {
		t.Error("idle-expired session socket was not closed")
	}
	idleClose()

	job.SnmpDevice.Community = "second"
	second, secondClose, err := state.dial(context.Background(), job)
	if err != nil {
		t.Fatalf("replacement dial: %v", err)
	}
	defer secondClose()
	secondConn := second.(*rateLimitedQuerier).q.(*gosnmp.GoSNMP)
	if secondConn == idleConn {
		t.Fatal("credential change reused the cached session")
	}
	if _, err := idleConn.Conn.Write([]byte("x")); err == nil {
		t.Error("replaced session socket was not closed")
	}
}

// The limiter wait counter counts real blocking from the per-device bucket.
func TestWaitSNMPBucketsReportsWaitMetric(t *testing.T) {
	device := newTokenBucket(100, nil)
	for range 11 { // burst of 10 plus the charge under test
		device.charge()
	}
	before := processMetrics.rateLimitWaitNs.Load()
	if !waitSNMPBuckets(context.Background(), device) {
		t.Fatal("waitSNMPBuckets failed without cancellation")
	}
	waited := time.Duration(processMetrics.rateLimitWaitNs.Load() - before)
	if waited < 5*time.Millisecond {
		t.Fatalf("rate-limit wait metric = %v, want the ~10ms device debt", waited)
	}
	if snmpRateLimitWaitMillis() < uint64(waited.Milliseconds()) {
		t.Fatal("millisecond heartbeat value lost the recorded wait")
	}
}
