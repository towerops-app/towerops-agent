// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func TestSnmpOIDLessArcs(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", false},
		{"", ".1", true},
		{".1", "", false},
		{"abc", "abd", true}, // malformed arcs compare lexically
		{"abd", "abc", false},
		{"same", "same", false}, // equal malformed arcs fall through
		{".1.2", ".1.10", true},
		{".1.10", ".1.2", false},
		{".1.2", ".1.2", false},
		{".1.2", ".1.2.3", true},
		{".1.2.3", ".1.2", false},
		{".9999999999999999999999", ".1", false}, // unparseable arc fallback
	}
	for _, c := range cases {
		if got := snmpOIDLess(c.a, c.b); got != c.want {
			t.Errorf("snmpOIDLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseOIDArcBounds(t *testing.T) {
	if _, ok := parseOIDArc(""); ok {
		t.Error("empty arc must fail")
	}
	if _, ok := parseOIDArc("1234567890123456789012345"); ok {
		t.Error("oversized arc must fail")
	}
	if _, ok := parseOIDArc("12a4"); ok {
		t.Error("non-numeric arc must fail")
	}
	if _, ok := parseOIDArc("18446744073709551616"); ok {
		t.Error("uint64 overflow must fail")
	}
	if v, ok := parseOIDArc("18446744073709551615"); !ok || v != ^uint64(0) {
		t.Errorf("max arc = %d, %v", v, ok)
	}
}

func TestNextOIDArc(t *testing.T) {
	if arc, next := nextOIDArc(".1.2", 9); arc != "" || next != 9 {
		t.Errorf("past-end arc = %q, %d", arc, next)
	}
	if arc, next := nextOIDArc("1.2.3", 2); arc != "2" || next != 4 {
		t.Errorf("middle arc = %q, %d", arc, next)
	}
	if arc, next := nextOIDArc("123", 0); arc != "123" || next != 3 {
		t.Errorf("final arc = %q, %d", arc, next)
	}
}

func TestSNMPDeviceStateTuners(t *testing.T) {
	s := newSNMPDeviceState(10)
	s.rememberGETSize(0)
	s.rememberGETSize(snmpMaxOIDsPerGet + 1)
	if got := s.getSize(); got == snmpMaxOIDsPerGet+1 {
		t.Error("out-of-range batch size must be ignored")
	}
	s.rememberGETSize(7)
	if got := s.getSize(); got != 7 {
		t.Errorf("batch size = %d", got)
	}
	if got := s.noteTooBig(); got != s.bulkMaxRepetition {
		t.Errorf("noteTooBig = %d", got)
	}
	s.bulkMaxRepetition = 1
	if got := s.noteTooBig(); got != 1 {
		t.Error("noteTooBig must floor at 1")
	}
	s.noteBulkRows(0)
	s.noteBulkRows(200)
	if s.bulkMaxRepetition != 64 {
		t.Errorf("bulk repetition clamp = %d, want 64", s.bulkMaxRepetition)
	}
}

func TestSNMPStateKey(t *testing.T) {
	if got := snmpStateKey(&pb.AgentJob{DeviceId: "d1"}); got != "id:d1" {
		t.Errorf("id key = %q", got)
	}
	if got := snmpStateKey(&pb.AgentJob{}); got != "unknown" {
		t.Errorf("empty job key = %q", got)
	}
	job := &pb.AgentJob{SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161, Transport: "udp"}}
	if got := snmpStateKey(job); got != "address:10.0.0.1:161:udp" {
		t.Errorf("address key = %q", got)
	}
	if state := newSNMPEngine().state(job); state == nil {
		t.Error("engine must mint per-device state")
	}
}

func TestSNMPPingUnreachable(t *testing.T) {
	reachabilityMu.Lock()
	delete(reachByDevice, "dev-gone")
	delete(reachByIP, "10.1.1.1")
	reachabilityMu.Unlock()

	job := &pb.AgentJob{DeviceId: "dev-gone", SnmpDevice: &pb.SnmpDevice{Ip: "10.1.1.1"}}
	if snmpPingUnreachable(job) {
		t.Error("no reachability data must not skip polling")
	}
	publishReachability("dev-gone", nil, false, 0, 100)
	if !snmpPingUnreachable(job) {
		t.Error("unreachable device id must skip polling")
	}
	// A device without a DeviceId falls back to the IP lookup.
	ipJob := &pb.AgentJob{SnmpDevice: &pb.SnmpDevice{Ip: "10.9.8.7"}}
	publishReachability("", net.ParseIP("10.9.8.7"), false, 0, 100)
	if !snmpPingUnreachable(ipJob) {
		t.Error("unreachable ip must skip polling")
	}
	defer func() {
		reachabilityMu.Lock()
		delete(reachByDevice, "dev-gone")
		delete(reachByIP, "10.9.8.7")
		reachabilityMu.Unlock()
	}()
}

func TestIsSNMPTimeoutKinds(t *testing.T) {
	if isSNMPTimeout(nil) {
		t.Error("nil is not a timeout")
	}
	if isSNMPTimeout(context.Canceled) {
		t.Error("canceled is not a timeout")
	}
	if !isSNMPTimeout(context.DeadlineExceeded) {
		t.Error("deadline is a timeout")
	}
	// A net.Error timeout.
	if !isSNMPTimeout(&net.DNSError{IsTimeout: true}) {
		t.Error("net timeout must count")
	}
	// A wrapped timeout message without net.Error.
	if !isSNMPTimeout(errors.New("snmp: request timeout")) {
		t.Error("timeout text must count")
	}
	if !isSNMPTimeout(errors.New("request timed out")) {
		t.Error("timed-out text must count")
	}
	if isSNMPTimeout(errors.New("connection refused")) {
		t.Error("refused is not a timeout")
	}
}

func TestWaitForSNMPAdmission(t *testing.T) {
	if !waitForSNMPAdmission(context.Background(), &pb.AgentJob{}) {
		t.Error("no device must admit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job := &pb.AgentJob{DeviceId: "cov-admit", SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.2"}}
	if waitForSNMPAdmission(ctx, job) {
		t.Error("cancelled ctx must refuse")
	}
	resetSNMPDeviceState(job)
}

func TestCloseIdleAndReset(t *testing.T) {
	job := &pb.AgentJob{DeviceId: "cov-reset", SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.3"}}
	state := defaultSNMPEngine.state(job)
	if state == nil {
		t.Fatal("state")
	}
	// TryLock branch: hold the session mutex so closeIdle skips.
	state.sessionMu.Lock()
	state.closeIdle(time.Now(), false)
	state.sessionMu.Unlock()
	// No session: both modes are no-ops.
	state.closeIdle(time.Now(), false)
	state.closeIdle(time.Now(), true)
	resetSNMPDeviceState(job)
	if _, ok := defaultSNMPEngine.devices[snmpStateKey(job)]; ok {
		t.Error("state must be deleted")
	}
	resetSNMPDeviceState(job) // absent state is a no-op
	expireSNMPSessions(time.Now())
	closeSNMPSessions()
}

func TestProbeSilentSNMPPaths(t *testing.T) {
	ctx := context.Background()
	job := &pb.AgentJob{DeviceId: "cov-probe", SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.4"}}
	state := newSNMPDeviceState(10)
	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })

	// Dial failure propagates.
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return nil, nil, errors.New("dial refused")
	}
	if err := probeSilentSNMP(ctx, job, state); err == nil {
		t.Error("dial error must propagate")
	}

	// GET error propagates.
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return nil, errors.New("get timeout")
		}}, func() {}, nil
	}
	if err := probeSilentSNMP(ctx, job, state); err == nil {
		t.Error("get error must propagate")
	}

	// Packet error status propagates.
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{Error: gosnmp.NoSuchName, ErrorIndex: 1}, nil
		}}, func() {}, nil
	}
	if err := probeSilentSNMP(ctx, job, state); err == nil {
		t.Error("packet error must propagate")
	}

	// Success.
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: 1},
			}}, nil
		}}, func() {}, nil
	}
	if err := probeSilentSNMP(ctx, job, state); err != nil {
		t.Errorf("probe success: %v", err)
	}
}

func TestSnmpJobQuerierObservation(t *testing.T) {
	obs := &snmpObservation{}
	state := newSNMPDeviceState(10)
	q := &snmpJobQuerier{q: &mockSnmpQuerier{}, state: state, observation: obs}
	if _, err := q.Get([]string{".1.3"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !obs.responded {
		t.Error("observation must record the response")
	}
	// Error path: observation counts the timeout.
	q.q = &mockSnmpQuerier{
		getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return nil, context.DeadlineExceeded
		},
		nextFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			return nil, context.DeadlineExceeded
		},
		getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
			return nil, context.DeadlineExceeded
		},
	}
	_, _ = q.Get([]string{".1.3"})
	_, _ = q.GetNext([]string{".1.3"})
	_, _ = q.GetBulk([]string{".1.3"}, 0, 10)
}

func TestExecuteSnmpJobSilentProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-silent",
		DeviceId:   "cov-silent-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.5", Community: "public", Version: "2c"},
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	state := defaultSNMPEngine.state(job)
	state.markSilent()
	if !state.isSilent() {
		t.Fatal("markSilent")
	}

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })

	// Silent + no ping hint → probe runs; its failure ships a partial.
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return nil, nil, errors.New("probe dial refused")
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}

	// Silent + unreachable ping hint skips the probe entirely.
	publishReachability("cov-silent-dev", nil, false, 0, 100)
	defer func() {
		reachabilityMu.Lock()
		delete(reachByDevice, "cov-silent-dev")
		reachabilityMu.Unlock()
	}()
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		t.Error("unreachable ping hint must skip the probe")
		return nil, nil, errors.New("x")
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
}

func TestExecuteSnmpJobDialAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-dial",
		DeviceId:   "cov-dial-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.6", Community: "public", Version: "2c"},
		DeadlineMs: 5000,
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return nil, nil, errors.New("connect refused")
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
}

func TestExecuteSnmpJobRateLimitedConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newResultQueueForAgent(ctx, 8)
	job := &pb.AgentJob{
		JobId:      "cov-limited",
		DeviceId:   "cov-limited-dev",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.7", Community: "public", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_GET,
			Oids:      []string{".1.3.6.1.2.1.1.1.0"},
		}},
	}
	t.Cleanup(func() { resetSNMPDeviceState(job) })

	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(dialCtx context.Context, j *pb.AgentJob) (snmpQuerier, func(), error) {
		limited := &rateLimitedQuerier{
			ctx:    dialCtx,
			cached: true,
			device: newTokenBucket(1000, nil),
			q: &mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				vars := make([]gosnmp.SnmpPDU, len(oids))
				for i, oid := range oids {
					vars[i] = gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: "x"}
				}
				return &gosnmp.SnmpPacket{Variables: vars}, nil
			}},
		}
		return limited, func() {}, nil
	}
	executeSnmpJob(ctx, job, out)
	select {
	case res := <-out.items:
		if res.event != "result" {
			t.Errorf("event = %q", res.event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
}

func TestSnmpWalkRootsPaths(t *testing.T) {
	ctx := context.Background()

	// Empty root set is a no-op.
	if buckets, errs := snmpWalkRoots(ctx, &mockSnmpQuerier{}, nil, false, nil); buckets != nil || errs != nil {
		t.Error("empty roots must return nil")
	}

	// Empty and dot roots normalize to the internet subtree.
	st := newSnmpWalkRootState("")
	if st.root != ".1.3.6.1" {
		t.Errorf("empty root = %q", st.root)
	}
	st = newSnmpWalkRootState(".")
	if st.root != ".1.3.6.1" {
		t.Errorf("dot root = %q", st.root)
	}
	st = newSnmpWalkRootState("1.3.6")
	if st.root != ".1.3.6" {
		t.Errorf("root = %q", st.root)
	}

	// tooBig halves repetitions; at 1 the walk errors out.
	state := newSNMPDeviceState(10)
	state.bulkMaxRepetition = 1
	bulk := &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Error: gosnmp.TooBig, ErrorIndex: 0}, nil
	}}
	_, errs := snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, state)
	if len(errs) != 1 || errs[0].err == nil {
		t.Errorf("tooBig at 1 must error: %v", errs)
	}

	// A non-NoError packet status errors the walk.
	state = newSNMPDeviceState(10)
	bulk = &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Error: gosnmp.AuthorizationError, ErrorIndex: 1}, nil
	}}
	_, errs = snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, state)
	if len(errs) != 1 || errs[0].err == nil {
		t.Errorf("auth error must error: %v", errs)
	}

	// An empty varbind list errors the walk.
	bulk = &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{}, nil
	}}
	_, errs = snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, nil)
	if len(errs) != 1 || errs[0].err == nil {
		t.Errorf("empty varbinds must error: %v", errs)
	}

	// GetBulk transport error records noResponse for timeouts.
	bulk = &mockSnmpQuerier{getBulkFunc: func(oids []string, nr uint8, mr uint32) (*gosnmp.SnmpPacket, error) {
		return nil, context.DeadlineExceeded
	}}
	_, errs = snmpWalkRoots(ctx, bulk, []string{".1.3.6.1"}, false, nil)
	if len(errs) != 1 || !errs[0].noResponse {
		t.Errorf("timeout must mark noResponse: %+v", errs)
	}
}

func TestSnmpWalkAbsorbPaths(t *testing.T) {
	st := newSnmpWalkRootState(".1.3.6.1")

	// EndOfMibView on the first PDU is an exact-leaf marker.
	done, exact, err := st.absorb(gosnmp.SnmpPDU{Name: ".1.3.6.1", Type: gosnmp.EndOfMibView})
	if !done || !exact || err != nil {
		t.Errorf("end-of-mib: %v %v %v", done, exact, err)
	}

	// A PDU outside the subtree ends the walk as exact on first row.
	st = newSnmpWalkRootState(".1.3.6.1")
	done, exact, err = st.absorb(gosnmp.SnmpPDU{Name: ".1.3.6.9", Type: gosnmp.Integer, Value: 1})
	if !done || !exact || err != nil {
		t.Errorf("escaped root: %v %v %v", done, exact, err)
	}

	// Non-increasing OIDs are a device error.
	st = newSnmpWalkRootState(".1.3.6.1")
	pdu := gosnmp.SnmpPDU{Name: ".1.3.6.1.5", Type: gosnmp.Integer, Value: 1}
	if _, _, err := st.absorb(pdu); err != nil {
		t.Fatalf("first absorb: %v", err)
	}
	done, _, err = st.absorb(gosnmp.SnmpPDU{Name: ".1.3.6.1.5", Type: gosnmp.Integer, Value: 2})
	if !done || err == nil {
		t.Errorf("non-increasing must error: %v %v", done, err)
	}
}

func TestSnmpWalkFinishExact(t *testing.T) {
	st := newSnmpWalkRootState(".1.3.6.1.2.1.1.1.0")

	// GET error records timeout-ness.
	st.err = nil
	st.finishExact(&mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
		return nil, context.DeadlineExceeded
	}})
	if st.err == nil || !st.noResponse || !st.done {
		t.Errorf("timeout exact: %+v", st)
	}

	// Packet error status.
	st = newSnmpWalkRootState(".1.3.6.1.2.1.1.1.0")
	st.finishExact(&mockSnmpQuerier{getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Error: gosnmp.NoSuchName, ErrorIndex: 1}, nil
	}})
	if st.err == nil || !st.done {
		t.Errorf("status exact: %+v", st)
	}
}
