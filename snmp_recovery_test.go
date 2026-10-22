// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func recoveryOIDs(count int) []string {
	oids := make([]string, count)
	for i := range oids {
		oids[i] = fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.6.%d", i+1)
	}
	return oids
}

func recoveryValues(batch []string) *gosnmp.SnmpPacket {
	vars := make([]gosnmp.SnmpPDU, len(batch))
	for i, oid := range batch {
		vars[i] = gosnmp.SnmpPDU{Name: "." + canonicalOID(oid), Type: gosnmp.OctetString, Value: []byte("value:" + canonicalOID(oid))}
	}
	return &gosnmp.SnmpPacket{Variables: vars}
}

func recoveryAbsent(batch []string, index uint8) *gosnmp.SnmpPacket {
	vars := make([]gosnmp.SnmpPDU, len(batch))
	for i, oid := range batch {
		vars[i] = gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Null}
	}
	return &gosnmp.SnmpPacket{Error: gosnmp.NoSuchName, ErrorIndex: index, Variables: vars}
}

func TestSnmpGetIntoIndexedNoSuchNameRecovery(t *testing.T) {
	large := recoveryOIDs(54)
	tests := []struct {
		name string
		oids []string
		bad  []string
	}{
		{name: "empty_batch"},
		{name: "54_one_bad", oids: large, bad: []string{large[4]}},
		{name: "54_ten_bad", oids: large, bad: slices.Clone(large[4:14])},
		{name: "first_bad", oids: large[:4], bad: []string{large[0]}},
		{name: "last_bad", oids: large[:4], bad: []string{large[3]}},
		{name: "all_bad", oids: large[:4], bad: large[:4]},
		{
			name: "duplicates_and_dotted",
			oids: []string{"." + large[0], large[1], large[0], "." + large[1], "." + large[2]},
			bad:  []string{large[1]},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Include unused capacity so removing from the caller's backing
			// array cannot hide behind an unchanged slice length.
			backing := make([]string, len(tt.oids)+2)
			copy(backing, tt.oids)
			backing[len(tt.oids)] = "sentinel-one"
			backing[len(tt.oids)+1] = "sentinel-two"
			original := slices.Clone(backing)
			oids := backing[:len(tt.oids)]
			badInstances := 0
			want := make(map[string]string)
			for _, oid := range oids {
				key := canonicalOID(oid)
				want[key] = "value:" + key
				if slices.Contains(tt.bad, key) {
					badInstances++
					want[key] = ""
				}
			}
			wantCalls := badInstances + 1
			if badInstances == len(oids) {
				wantCalls = badInstances
			}
			var requests [][]string
			mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
				requests = append(requests, slices.Clone(batch))
				if len(requests) > 2*len(oids) {
					t.Fatal("recovery exceeded the bounded request count")
				}
				for i, oid := range batch {
					if slices.Contains(tt.bad, canonicalOID(oid)) {
						return recoveryAbsent(batch, uint8(i+1)), nil
					}
				}
				return recoveryValues(batch), nil
			}}
			values := make(map[string]string)
			absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"}, oids, values)
			if err != nil {
				t.Fatalf("collection failed: %v", err)
			}
			if absent != badInstances {
				t.Errorf("absent = %d, want %d", absent, badInstances)
			}
			if len(requests) != wantCalls {
				t.Errorf("GET requests = %d, want %d", len(requests), wantCalls)
			}
			for i, batch := range requests {
				if len(batch) != len(oids)-i {
					t.Errorf("request %d has %d OIDs, want %d", i+1, len(batch), len(oids)-i)
				}
			}
			if !slices.Equal(backing, original) {
				t.Errorf("caller input changed: got %v, want %v", backing, original)
			}
			if len(values) != len(want) {
				t.Fatalf("values = %v, want %v", values, want)
			}
			for oid, value := range want {
				if got, ok := values[oid]; !ok || got != value {
					t.Errorf("values[%q] = %q (present %v), want %q", oid, got, ok, value)
				}
			}
		})
	}
}

func TestExecuteSnmpJobIndexedRecovery(t *testing.T) {
	oids := recoveryOIDs(54)
	badOID := oids[4]
	calls := 0
	mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
		calls++
		if calls > 2*len(oids) {
			t.Fatal("recovery exceeded the bounded request count")
		}
		for i, oid := range batch {
			if canonicalOID(oid) == badOID {
				return recoveryAbsent(batch, uint8(i+1)), nil
			}
		}
		return recoveryValues(batch), nil
	}}
	orig := snmpDial
	t.Cleanup(func() { snmpDial = orig })
	snmpDial = func(context.Context, *pb.AgentJob) (snmpQuerier, func(), error) {
		return mock, func() {}, nil
	}
	out := newResultQueue(2)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId: "indexed-recovery", DeviceId: "device-one",
		SnmpDevice: &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"},
		Queries:    []*pb.SnmpQuery{{QueryType: pb.QueryType_GET, Oids: oids}},
	}, out)
	result := decodeQueuedResult[*pb.SnmpResult](t, <-out.items)
	if calls != 2 {
		t.Errorf("GET requests = %d, want 2", calls)
	}
	if len(result.OidValues) != len(oids) {
		t.Fatalf("returned %d OIDs, want %d", len(result.OidValues), len(oids))
	}
	for _, oid := range oids {
		want := "value:" + oid
		if oid == badOID {
			want = ""
		}
		if value, ok := result.OidValues[oid]; !ok || value != want {
			t.Errorf("result[%q] = %q (present %v), want %q", oid, value, ok, want)
		}
	}
}

func TestSnmpGetIntoMalformedNoSuchNameIndex(t *testing.T) {
	for _, index := range []uint8{0, 5, 255} {
		t.Run(fmt.Sprintf("index_%d", index), func(t *testing.T) {
			oids := recoveryOIDs(4)
			original := slices.Clone(oids)
			badOID := oids[1]
			calls := 0
			mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
				calls++
				if calls > 2*len(oids)-1 {
					t.Fatal("malformed-index fallback exceeded binary split bound")
				}
				if slices.Contains(batch, badOID) {
					return recoveryAbsent(batch, index), nil
				}
				return recoveryValues(batch), nil
			}}
			values := make(map[string]string)
			absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"}, oids, values)
			if err != nil || absent != 1 {
				t.Fatalf("absent = %d, error = %v; want one absent and no error", absent, err)
			}
			if !slices.Equal(oids, original) {
				t.Errorf("caller input changed: %v", oids)
			}
			if len(values) != len(oids) {
				t.Fatalf("values = %v, want every supported or absent OID", values)
			}
			for _, oid := range oids {
				want := "value:" + oid
				if oid == badOID {
					want = ""
				}
				if value, ok := values[oid]; !ok || value != want {
					t.Errorf("values[%q] = %q (present %v), want %q", oid, value, ok, want)
				}
			}
		})
	}
}

func TestSnmpGetIntoIndexedRemovalThenTimeout(t *testing.T) {
	oids := recoveryOIDs(4)
	original := slices.Clone(oids)
	timeout := errors.New("request timeout")
	calls := 0
	mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
		calls++
		if calls > 2*len(oids)-1 {
			t.Fatal("recovery exceeded the bounded request count")
		}
		if calls == 1 {
			return recoveryAbsent(batch, 1), nil
		}
		return nil, timeout
	}}
	values := map[string]string{"1.3.6.1.2.1.1.1.0": "earlier success"}
	absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"}, oids, values)
	if !errors.Is(err, timeout) {
		t.Errorf("error = %v, want wrapped timeout", err)
	}
	if calls != 2 || absent != 1 {
		t.Errorf("GET requests = %d, absent = %d; want 2 and 1", calls, absent)
	}
	if value, ok := values[oids[0]]; !ok || value != "" {
		t.Errorf("absent OID marker = %q (present %v), want empty and present", value, ok)
	}
	for _, oid := range oids[1:] {
		if _, ok := values[oid]; ok {
			t.Errorf("timed-out OID %q was recorded as collected", oid)
		}
	}
	if values["1.3.6.1.2.1.1.1.0"] != "earlier success" {
		t.Error("earlier successful value was lost")
	}
	if !slices.Equal(oids, original) {
		t.Errorf("caller input changed: %v", oids)
	}
}

func TestSnmpGetIntoSplitPreservesSuccessfulSibling(t *testing.T) {
	tests := []struct {
		status       gosnmp.SNMPError
		successStart int
	}{
		{gosnmp.NoSuchName, 0},
		{gosnmp.NoSuchName, 2},
		{gosnmp.TooBig, 0},
		{gosnmp.TooBig, 2},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_success_%d", tt.status, tt.successStart), func(t *testing.T) {
			oids := recoveryOIDs(4)
			timeout := errors.New("request timeout")
			calls := 0
			mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
				calls++
				if calls > 3 {
					t.Fatal("unexpected request after a split sibling failed")
				}
				if len(batch) == len(oids) {
					return &gosnmp.SnmpPacket{Error: tt.status}, nil
				}
				if batch[0] == oids[tt.successStart] {
					return recoveryValues(batch), nil
				}
				return nil, timeout
			}}
			values := make(map[string]string)
			absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"}, oids, values)
			if !errors.Is(err, timeout) || absent != 0 || calls != 3 {
				t.Fatalf("error = %v, absent = %d, requests = %d; want timeout, 0, 3", err, absent, calls)
			}
			if len(values) != 2 {
				t.Fatalf("values = %v, want only successful sibling", values)
			}
			for _, oid := range oids[tt.successStart : tt.successStart+2] {
				if values[oid] != "value:"+oid {
					t.Errorf("successful sibling %q was not retained", oid)
				}
			}
		})
	}
}

func TestSnmpGetIntoIndexedRemovalThenFallback(t *testing.T) {
	oids := recoveryOIDs(4)
	original := slices.Clone(oids)
	calls := 0
	mock := &mockSnmpQuerier{getFunc: func(batch []string) (*gosnmp.SnmpPacket, error) {
		calls++
		if calls > 2*len(oids)-1 {
			t.Fatal("mixed recovery exceeded the bounded request count")
		}
		if len(batch) == len(oids) {
			return recoveryAbsent(batch, 2), nil
		}
		if len(batch) == 3 {
			return &gosnmp.SnmpPacket{Error: gosnmp.TooBig}, nil
		}
		if slices.Contains(batch, oids[2]) {
			return recoveryAbsent(batch, 0), nil
		}
		return recoveryValues(batch), nil
	}}
	values := make(map[string]string)
	absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "192.0.2.1", Version: "1"}, oids, values)
	if err != nil || absent != 2 {
		t.Fatalf("absent = %d, error = %v; want two absent and no error", absent, err)
	}
	if calls != 6 {
		t.Errorf("GET requests = %d, want 6", calls)
	}
	if len(values) != len(oids) {
		t.Fatalf("values = %v, want supported values and both absent markers", values)
	}
	for i, oid := range oids {
		want := "value:" + oid
		if i == 1 || i == 2 {
			want = ""
		}
		if value, ok := values[oid]; !ok || value != want {
			t.Errorf("values[%q] = %q (present %v), want %q", oid, value, ok, want)
		}
	}
	if !slices.Equal(oids, original) {
		t.Errorf("caller input changed: %v", oids)
	}
}
