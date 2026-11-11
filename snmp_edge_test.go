// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

// A leaf root that is the last object in the device's MIB view: the first
// GETNEXT/GETBULK answers end-of-view (v1: noSuchName) instead of escaping
// the subtree, and the walk must still fall back to one exact GET.
func TestSnmpWalkAllLeafRootAtEndOfMibUsesExactGet(t *testing.T) {
	const root = ".1.3.6.1.4.1.9999.1.0"
	leaf := func([]string) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{
			Name: root, Type: gosnmp.Integer, Value: 7,
		}}}, nil
	}
	bulkAnswer := func(typ gosnmp.Asn1BER) func([]string, uint8, uint32) (*gosnmp.SnmpPacket, error) {
		return func([]string, uint8, uint32) (*gosnmp.SnmpPacket, error) {
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: root, Type: typ}}}, nil
		}
	}
	cases := []struct {
		name string
		v1   bool
		mock *mockSnmpQuerier
	}{
		{name: "endOfMibView", mock: &mockSnmpQuerier{getFunc: leaf, getBulkFunc: bulkAnswer(gosnmp.EndOfMibView)}},
		{name: "noSuchObject", mock: &mockSnmpQuerier{getFunc: leaf, getBulkFunc: bulkAnswer(gosnmp.NoSuchObject)}},
		{name: "noSuchInstance", mock: &mockSnmpQuerier{getFunc: leaf, getBulkFunc: bulkAnswer(gosnmp.NoSuchInstance)}},
		// The default GETNEXT mock answers v1 noSuchName.
		{name: "v1 noSuchName", v1: true, mock: &mockSnmpQuerier{getFunc: leaf}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := snmpWalkAll(context.Background(), tc.mock, root, tc.v1)
			if err != nil {
				t.Fatalf("leaf walk = %v, want the root collected", err)
			}
			if len(tc.mock.getRequests) != 1 || tc.mock.getRequests[0] != root {
				t.Errorf("exact GETs = %v, want one GET of %s", tc.mock.getRequests, root)
			}
			if len(results) != 1 || results[0].Name != root {
				t.Errorf("collected = %v, want the leaf varbind", results)
			}
		})
	}
}

// Past the first request, end-of-view is the normal end of a table walk and
// must not trigger an exact GET.
func TestSnmpWalkAllEndOfMibAfterRowsSkipsExactGet(t *testing.T) {
	const root = ".1.3.6.1.2.1.2"
	mock := &mockSnmpQuerier{getBulkFunc: bulkTable(map[string]*gosnmp.SnmpPacket{
		root: {Variables: []gosnmp.SnmpPDU{{Name: root + ".1", Type: gosnmp.Integer, Value: 1}}},
	})}
	results, err := snmpWalkAll(context.Background(), mock, root, false)
	if err != nil || len(results) != 1 {
		t.Fatalf("walk = %v, %v; want one row and a clean end", results, err)
	}
	if len(mock.getRequests) != 0 {
		t.Errorf("exact GETs = %v, want none", mock.getRequests)
	}
}

// Unknown v3 levels must fail the job: falling through to noAuthNoPriv
// sends unauthenticated requests for a credential meant to authenticate.
func TestNewSnmpConnRejectsUnknownV3SecurityLevel(t *testing.T) {
	for _, level := range []string{"authpriv", "auth_priv", "AuthPriv"} {
		t.Run(level, func(t *testing.T) {
			conn, err := newSnmpConn(context.Background(), &pb.SnmpDevice{
				Ip: "127.0.0.1", Version: "v3", V3Username: "user", V3SecurityLevel: level,
				V3AuthProtocol: "SHA", V3AuthPassword: "pass1234",
			})
			if err == nil {
				_ = conn.Conn.Close()
				t.Fatal("newSnmpConn error = nil, want unsupported security level")
			}
			want := fmt.Sprintf("unsupported SNMPv3 security level %q", level)
			if err.Error() != want {
				t.Errorf("newSnmpConn error = %q, want %q", err.Error(), want)
			}
		})
	}
}

// The server sends "" for a credential without a stored level.
func TestNewSnmpConnEmptyV3SecurityLevelIsNoAuthNoPriv(t *testing.T) {
	conn, err := newSnmpConn(context.Background(), &pb.SnmpDevice{Ip: "127.0.0.1", Version: "v3", V3Username: "user"})
	if err != nil {
		t.Fatalf("newSnmpConn error = %v, want nil", err)
	}
	defer func() { _ = conn.Conn.Close() }()
	// Connect sets the Reportable bit; the security level is the auth/priv bits.
	if level := conn.MsgFlags &^ gosnmp.Reportable; level != gosnmp.NoAuthNoPriv {
		t.Errorf("MsgFlags security level = %v, want NoAuthNoPriv", level)
	}
}

// A NoError reply that omits a requested varbind must record the OID as
// absent: otherwise the server cannot tell it was asked for, and the absent
// count that exposes a scoped credential undercounts.
func TestSnmpGetIntoShortReplyRecordsMissingOIDs(t *testing.T) {
	mock := &mockSnmpQuerier{getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
		return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("sw1")},
		}}, nil
	}}
	into := map[string]string{}
	absent, err := snmpGetInto(mock, &pb.SnmpDevice{Ip: "10.0.0.1"},
		[]string{".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.4.0"}, into)
	if err != nil {
		t.Fatalf("snmpGetInto error = %v", err)
	}
	if absent != 2 {
		t.Errorf("absent = %d, want 2", absent)
	}
	want := map[string]string{"1.3.6.1.2.1.1.5.0": "sw1", "1.3.6.1.2.1.1.6.0": "", "1.3.6.1.2.1.1.4.0": ""}
	if len(into) != len(want) {
		t.Fatalf("into = %v, want %v", into, want)
	}
	for k, v := range want {
		if got, ok := into[k]; !ok || got != v {
			t.Errorf("into[%q] = %q (present %t), want %q", k, got, ok, v)
		}
	}
}

// completed_roots and truncated_roots ride on top of the oid_values budget.
// 200 roots that fill the values budget must still leave room for the root
// lists and the channel envelope.
func TestSnmpResultFramesBudgetRootLists(t *testing.T) {
	const maxPayload = 1 << 20
	const roots = 200
	buckets := make([]snmpResultBucket, roots)
	for i := range buckets {
		label := fmt.Sprintf("1.3.6.1.4.1.99999.1.%03d", i)
		buckets[i] = snmpResultBucket{
			label:     label,
			values:    map[string]string{label + ".1": strings.Repeat("v", 3877)},
			completed: true,
		}
	}
	frames := buildSnmpResultFrames(&pb.AgentJob{JobId: "many-roots", MaxResultBytes: maxPayload}, buckets, false)
	values, claimed := 0, map[string]bool{}
	for i, f := range frames {
		if size := proto.Size(f); size > maxPayload*3/4-1024 {
			t.Errorf("frame %d decoded size %d leaves under 1 KiB of the %d-byte payload for the envelope", i, size, maxPayload)
		}
		values += len(f.OidValues)
		for _, r := range f.CompletedRoots {
			claimed[r] = true
		}
	}
	if values != roots || len(claimed) != roots {
		t.Errorf("frames carry %d values and %d roots, want %d of each", values, len(claimed), roots)
	}
}
