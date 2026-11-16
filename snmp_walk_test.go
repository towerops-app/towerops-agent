// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// multiBulkScript answers GETBULK requests with scripted packets, recording
// each request's roots and max-repetitions.
type multiBulkScript struct {
	requests [][]string
	reps     []uint32
	packets  []*gosnmp.SnmpPacket
}

func (m *multiBulkScript) bulk(oids []string, _ uint8, repetitions uint32) (*gosnmp.SnmpPacket, error) {
	m.requests = append(m.requests, append([]string(nil), oids...))
	m.reps = append(m.reps, repetitions)
	if len(m.packets) == 0 {
		return nil, errors.New("unexpected GETBULK")
	}
	packet := m.packets[0]
	m.packets = m.packets[1:]
	return packet, nil
}

func intVar(oid string, value int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: int64(value)}
}

func endVar(oid string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView}
}

// Two active roots ride one GETBULK per round; a root that answers
// EndOfMibView drops out, so the last request names only the surviving root.
func TestSnmpWalkRootsSharesBulksUntilExhausted(t *testing.T) {
	const a = ".1.3.6.1.2.100"
	const b = ".1.3.6.1.2.200"
	script := &multiBulkScript{packets: []*gosnmp.SnmpPacket{
		{Variables: []gosnmp.SnmpPDU{
			intVar(a+".1", 1), intVar(b+".1", 1),
			intVar(a+".2", 2), intVar(b+".2", 2),
			endVar(a), intVar(b+".3", 3),
		}},
		{Variables: []gosnmp.SnmpPDU{endVar(b)}},
	}}
	mock := &mockSnmpQuerier{getBulkFunc: script.bulk}

	state := newSNMPDeviceState(defaultSNMPDevicePDURate)
	buckets, errs := snmpWalkRoots(context.Background(), mock, []string{a, b}, false, state)
	if len(errs) != 2 {
		t.Fatalf("root errors = %v, want two outcomes", errs)
	}
	for _, rootErr := range errs {
		if rootErr.err != nil {
			t.Fatalf("root %s failed: %v", rootErr.root, rootErr.err)
		}
	}
	wantA := map[string]string{a[1:] + ".1": "1", a[1:] + ".2": "2"}
	wantB := map[string]string{b[1:] + ".1": "1", b[1:] + ".2": "2", b[1:] + ".3": "3"}
	if !maps.Equal(buckets[0].values, wantA) {
		t.Fatalf("root A values = %v, want %v", buckets[0].values, wantA)
	}
	if !maps.Equal(buckets[1].values, wantB) {
		t.Fatalf("root B values = %v, want %v", buckets[1].values, wantB)
	}
	if len(script.requests) != 2 || len(script.requests[0]) != 2 || len(script.requests[1]) != 1 ||
		script.requests[0][0] != a || script.requests[0][1] != b || script.requests[1][0] != b+".3" {
		t.Fatalf("GETBULK requests = %v, want [A B] then [B]", script.requests)
	}
	if !buckets[0].completed || !buckets[1].completed {
		t.Fatal("exhausted shared roots must both claim completion")
	}
}

// A full GETBULK response raises the device's remembered max-repetitions;
// tooBig halves it before retrying the identical cursor.
func TestSnmpWalkRootsAdaptsMaxRepetitions(t *testing.T) {
	root := ".1.3.6.1.2.300"
	full := make([]gosnmp.SnmpPDU, 25)
	for i := range full {
		full[i] = intVar(fmt.Sprintf("%s.%d", root, i+1), i+1)
	}
	script := &multiBulkScript{packets: []*gosnmp.SnmpPacket{
		{Error: gosnmp.TooBig},
		{Variables: full},
		{Variables: []gosnmp.SnmpPDU{endVar(root)}},
	}}
	mock := &mockSnmpQuerier{getBulkFunc: script.bulk}

	state := newSNMPDeviceState(defaultSNMPDevicePDURate)
	buckets, errs := snmpWalkRoots(context.Background(), mock, []string{root}, false, state)
	for _, rootErr := range errs {
		if rootErr.err != nil {
			t.Fatalf("root walk failed: %v", rootErr.err)
		}
	}
	if len(script.requests) != 3 || script.reps[0] != 25 || script.reps[1] != 12 {
		t.Fatalf("repetitions = %v, want 25 then a tooBig retry at 12", script.reps)
	}
	if got := state.bulkRepetitions(); got != 25 {
		t.Fatalf("remembered repetitions = %d, want the delivered full response count 25", got)
	}
	if len(buckets[0].values) != 25 || !buckets[0].completed {
		t.Fatalf("adaptive walk = %d values, completed %t", len(buckets[0].values), buckets[0].completed)
	}
}

// A GETBULK leaf root still falls back to one exact GET instead of walking
// into the next subtree.
func TestSnmpWalkRootsUsesExactGetForLeafRoot(t *testing.T) {
	root := ".1.3.6.1.4.1.999.1.0"
	next := ".1.3.6.1.4.1.999.2"
	mock := &mockSnmpQuerier{
		getBulkFunc: func([]string, uint8, uint32) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{intVar(next, 1)}}, nil
		},
		getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			if len(oids) != 1 || oids[0] != root {
				return nil, fmt.Errorf("exact GET requested %v", oids)
			}
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{intVar(root, 7)}}, nil
		},
	}
	state := newSNMPDeviceState(defaultSNMPDevicePDURate)
	buckets, errs := snmpWalkRoots(context.Background(), mock, []string{root}, false, state)
	if len(errs) != 1 || errs[0].err != nil {
		t.Fatalf("leaf walk errors = %v", errs)
	}
	if got := buckets[0].values[root[1:]]; got != "7" {
		t.Fatalf("leaf value = %q, want 7", got)
	}
	if len(mock.bulkRequests) != 1 || len(mock.getRequests) != 1 {
		t.Fatalf("requests = bulk %d, get %d; want one of each", len(mock.bulkRequests), len(mock.getRequests))
	}
}

// A device timeout inside a shared walk fails only the active roots and ends
// the job: the walk loop must not issue another request after zero responses.
func TestExecuteSnmpJobAbortsWalkAfterSilentResponse(t *testing.T) {
	const deviceID = "walk-timeout-device"
	origDial := snmpDial
	t.Cleanup(func() { snmpDial = origDial })
	root := ".1.3.6.1.2.400"
	requests := 0
	mock := &mockSnmpQuerier{
		getBulkFunc: func(oids []string, _ uint8, _ uint32) (*gosnmp.SnmpPacket, error) {
			requests++
			if requests == 1 {
				return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{intVar(root+".1", 1)}}, nil
			}
			return nil, errors.New("response timeout")
		},
	}
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return mock, func() {}, nil
	}
	resetJob := &pb.AgentJob{DeviceId: deviceID}
	t.Cleanup(func() { resetSNMPDeviceState(resetJob) })

	out := newResultQueue(4)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "walk-timeout",
		DeviceId:   deviceID,
		SnmpDevice: &pb.SnmpDevice{Ip: "192.0.2.4"},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_WALK, Oids: []string{root, root}},
			{QueryType: pb.QueryType_GET, Oids: []string{"1.3.6.1.2.1.1.1.0"}},
		},
	}, out)
	if requests != 2 {
		t.Fatalf("walk issued %d requests, want no request after the silent response", requests)
	}
	result := decodeQueuedResult[*pb.SnmpResult](t, <-out.items)
	value := result.OidValues[root[1:]+".1"]
	if !result.Partial || value != "1" {
		t.Fatalf("aborted walk result = %+v (value %q), want partial with the first row", result, value)
	}
	if notice := decodeQueuedResult[*pb.AgentError](t, <-out.items); !strings.Contains(notice.Message, "WALK "+root[1:]) {
		t.Fatalf("walk notice = %q", notice.Message)
	}
}
