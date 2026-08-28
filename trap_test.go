// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

func TestTrapToProtoV2c(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 41234}
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		PDUType:   gosnmp.SNMPv2Trap,
		Community: "public",
		Variables: []gosnmp.SnmpPDU{
			{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(987654)},
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.4"},
			{Name: ".1.3.6.1.2.1.2.2.1.1.7", Type: gosnmp.Integer, Value: 7},
			{Name: ".1.3.6.1.2.1.2.2.1.2.7", Type: gosnmp.OctetString, Value: []byte("ether7")},
		},
	}

	trap := trapToProto(packet, addr)

	if trap.Version != 2 {
		t.Errorf("Version = %d, want 2", trap.Version)
	}
	if trap.SourceIp != "192.0.2.10" {
		t.Errorf("SourceIp = %q, want %q", trap.SourceIp, "192.0.2.10")
	}
	if trap.UptimeTicks != 987654 {
		t.Errorf("UptimeTicks = %d, want 987654", trap.UptimeTicks)
	}
	if trap.TrapOid != "1.3.6.1.6.3.1.1.5.4" {
		t.Errorf("TrapOid = %q, want %q", trap.TrapOid, "1.3.6.1.6.3.1.1.5.4")
	}

	// v1-only header fields must stay zero for a v2c trap.
	if trap.Enterprise != "" {
		t.Errorf("Enterprise = %q, want empty", trap.Enterprise)
	}
	if trap.GenericTrap != 0 {
		t.Errorf("GenericTrap = %d, want 0", trap.GenericTrap)
	}
	if trap.SpecificTrap != 0 {
		t.Errorf("SpecificTrap = %d, want 0", trap.SpecificTrap)
	}

	want := map[string]string{
		"1.3.6.1.2.1.2.2.1.1.7": "7",
		"1.3.6.1.2.1.2.2.1.2.7": "ether7",
	}
	if len(trap.Varbinds) != len(want) {
		t.Fatalf("Varbinds = %v, want %d entries", trap.Varbinds, len(want))
	}
	for k, v := range want {
		if got := trap.Varbinds[k]; got != v {
			t.Errorf("Varbinds[%q] = %q, want %q", k, got, v)
		}
	}
	// The hoisted OIDs must not be duplicated into the varbind map, in either
	// the dotted or the trimmed form.
	for _, absent := range []string{oidSysUpTime, oidSnmpTrapOID, trimOID(oidSysUpTime), trimOID(oidSnmpTrapOID)} {
		if _, ok := trap.Varbinds[absent]; ok {
			t.Errorf("Varbinds contains hoisted OID %q", absent)
		}
	}
	if trap.Timestamp == 0 {
		t.Error("Timestamp = 0, want the receive time")
	}
}

func TestTrapToProtoV1(t *testing.T) {
	tests := []struct {
		name         string
		generic      int
		specific     int
		enterprise   string
		wantTrapOid  string
		wantSpecific uint32
	}{
		{
			name:        "generic link down",
			generic:     2,
			enterprise:  ".1.3.6.1.4.1.9",
			wantTrapOid: "1.3.6.1.6.3.1.1.5.3",
		},
		{
			name:         "enterprise specific",
			generic:      genericEnterpriseSpecific,
			specific:     42,
			enterprise:   ".1.3.6.1.4.1.9",
			wantTrapOid:  "1.3.6.1.4.1.9.0.42",
			wantSpecific: 42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 32100}
			packet := &gosnmp.SnmpPacket{
				Version:   gosnmp.Version1,
				PDUType:   gosnmp.Trap,
				Community: "public",
				SnmpTrap: gosnmp.SnmpTrap{
					Enterprise:   tt.enterprise,
					AgentAddress: "192.0.2.20",
					GenericTrap:  tt.generic,
					SpecificTrap: tt.specific,
					Timestamp:    4242,
				},
				Variables: []gosnmp.SnmpPDU{
					// A v1 trap carries uptime in the header; a stray sysUpTime
					// binding must not override it.
					{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(999)},
					{Name: ".1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
				},
			}

			trap := trapToProto(packet, addr)

			if trap.Version != 1 {
				t.Errorf("Version = %d, want 1", trap.Version)
			}
			if trap.Enterprise != "1.3.6.1.4.1.9" {
				t.Errorf("Enterprise = %q, want %q", trap.Enterprise, "1.3.6.1.4.1.9")
			}
			if trap.UptimeTicks != 4242 {
				t.Errorf("UptimeTicks = %d, want 4242 (from the v1 header)", trap.UptimeTicks)
			}
			if trap.TrapOid != tt.wantTrapOid {
				t.Errorf("TrapOid = %q, want %q", trap.TrapOid, tt.wantTrapOid)
			}
			if trap.GenericTrap != uint32(tt.generic) { //nolint:gosec // fixed test input
				t.Errorf("GenericTrap = %d, want %d", trap.GenericTrap, tt.generic)
			}
			if trap.SpecificTrap != tt.wantSpecific {
				t.Errorf("SpecificTrap = %d, want %d", trap.SpecificTrap, tt.wantSpecific)
			}
			if trap.SourceIp != "192.0.2.20" {
				t.Errorf("SourceIp = %q, want %q", trap.SourceIp, "192.0.2.20")
			}
			if len(trap.Varbinds) != 1 || trap.Varbinds["1.3.6.1.2.1.2.2.1.1.3"] != "3" {
				t.Errorf("Varbinds = %v, want the single ordinary binding", trap.Varbinds)
			}
		})
	}
}

func TestV1TrapOID(t *testing.T) {
	tests := []struct {
		name       string
		enterprise string
		generic    int
		specific   int
		want       string
	}{
		{name: "cold start", generic: 0, want: "1.3.6.1.6.3.1.1.5.1"},
		{name: "warm start", generic: 1, want: "1.3.6.1.6.3.1.1.5.2"},
		{name: "link down", generic: 2, want: "1.3.6.1.6.3.1.1.5.3"},
		{name: "link up", generic: 3, want: "1.3.6.1.6.3.1.1.5.4"},
		{name: "auth failure", generic: 4, want: "1.3.6.1.6.3.1.1.5.5"},
		{name: "egp neighbor loss", generic: 5, want: "1.3.6.1.6.3.1.1.5.6"},
		{
			name:       "enterprise specific",
			enterprise: "1.3.6.1.4.1.9",
			generic:    genericEnterpriseSpecific,
			specific:   7,
			want:       "1.3.6.1.4.1.9.0.7",
		},
		{
			name:     "enterprise specific without enterprise",
			generic:  genericEnterpriseSpecific,
			specific: 7,
			want:     "",
		},
		{name: "out of range generic", generic: 9, want: ""},
		{name: "negative generic", generic: -1, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v1TrapOID(tt.enterprise, tt.generic, tt.specific)
			if got != tt.want {
				t.Errorf("v1TrapOID(%q, %d, %d) = %q, want %q", tt.enterprise, tt.generic, tt.specific, got, tt.want)
			}
		})
	}
}

func TestTrapVersion(t *testing.T) {
	tests := []struct {
		input gosnmp.SnmpVersion
		want  uint32
	}{
		{gosnmp.Version1, 1},
		{gosnmp.Version2c, 2},
		{gosnmp.Version3, 3},
		{gosnmp.SnmpVersion(0x7f), 0},
	}
	for _, tt := range tests {
		got := trapVersion(tt.input)
		if got != tt.want {
			t.Errorf("trapVersion(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestUptimeTicks(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want uint64
	}{
		{
			name: "uint32 timeticks",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(123456)},
			want: 123456,
		},
		{
			name: "uint",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.Gauge32, Value: uint(654321)},
			want: 654321,
		},
		{
			name: "uint64",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.Counter64, Value: uint64(9876543210)},
			want: 9876543210,
		},
		{
			name: "positive int",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.Integer, Value: 42},
			want: 42,
		},
		{
			name: "negative int",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.Integer, Value: -5},
			want: 0,
		},
		{
			name: "parseable string",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.OctetString, Value: []byte("4242")},
			want: 4242,
		},
		{
			name: "unparseable value",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.OctetString, Value: []byte("12 days, 3:04")},
			want: 0,
		},
		{
			name: "null value",
			pdu:  gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.Null, Value: nil},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uptimeTicks(tt.pdu)
			if got != tt.want {
				t.Errorf("uptimeTicks(%v) = %d, want %d", tt.pdu.Value, got, tt.want)
			}
		})
	}
}

func TestTrapToProtoTruncatesVarbinds(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.30"), Port: 1024}
	vars := make([]gosnmp.SnmpPDU, 0, maxTrapVarbinds+10)
	for i := range maxTrapVarbinds + 10 {
		vars = append(vars, gosnmp.SnmpPDU{
			Name:  fmt.Sprintf(".1.3.6.1.4.1.99.1.%d", i),
			Type:  gosnmp.Integer,
			Value: i,
		})
	}
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		PDUType:   gosnmp.SNMPv2Trap,
		Variables: vars,
	}

	trap := trapToProto(packet, addr)

	if len(trap.Varbinds) != maxTrapVarbinds {
		t.Errorf("len(Varbinds) = %d, want %d", len(trap.Varbinds), maxTrapVarbinds)
	}
}

func TestTrapToProtoTrimsOIDs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{".1.3.6.1", "1.3.6.1"},
		{"1.3.6.1", "1.3.6.1"},
		{".", ""},
	}
	for _, tt := range tests {
		got := trimOID(tt.input)
		if got != tt.want {
			t.Errorf("trimOID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTrapListenerHandle(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.40"), Port: 5000}
	packet := func(community string) *gosnmp.SnmpPacket {
		return &gosnmp.SnmpPacket{
			Version:   gosnmp.Version2c,
			PDUType:   gosnmp.SNMPv2Trap,
			Community: community,
			Variables: []gosnmp.SnmpPDU{
				{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.1"},
			},
		}
	}

	t.Run("community mismatch is dropped", func(t *testing.T) {
		l := &trapListener{traps: make(chan *pb.SnmpTrap, 1), community: "secret"}
		l.handle(packet("public"), addr)
		if len(l.traps) != 0 {
			t.Errorf("queued %d traps, want 0", len(l.traps))
		}
		if got := l.dropped.Load(); got != 0 {
			t.Errorf("dropped = %d, want 0 (filtered, not dropped)", got)
		}
	})

	t.Run("community match is accepted", func(t *testing.T) {
		l := &trapListener{traps: make(chan *pb.SnmpTrap, 1), community: "secret"}
		l.handle(packet("secret"), addr)
		select {
		case trap := <-l.Traps():
			if trap.TrapOid != "1.3.6.1.6.3.1.1.5.1" {
				t.Errorf("TrapOid = %q, want %q", trap.TrapOid, "1.3.6.1.6.3.1.1.5.1")
			}
			if trap.SourceIp != "192.0.2.40" {
				t.Errorf("SourceIp = %q, want %q", trap.SourceIp, "192.0.2.40")
			}
		default:
			t.Fatal("no trap queued")
		}
	})

	t.Run("empty community filter accepts anything", func(t *testing.T) {
		l := &trapListener{traps: make(chan *pb.SnmpTrap, 1)}
		l.handle(packet("whatever"), addr)
		if len(l.traps) != 1 {
			t.Errorf("queued %d traps, want 1", len(l.traps))
		}
	})

	t.Run("full queue drops without blocking", func(t *testing.T) {
		l := &trapListener{traps: make(chan *pb.SnmpTrap, 1)}
		l.handle(packet("public"), addr)
		l.handle(packet("public"), addr)
		l.handle(packet("public"), addr)
		if len(l.traps) != 1 {
			t.Errorf("queued %d traps, want 1", len(l.traps))
		}
		if got := l.dropped.Load(); got != 2 {
			t.Errorf("dropped = %d, want 2", got)
		}
	})

	t.Run("nil packet and nil addr are ignored", func(t *testing.T) {
		l := &trapListener{traps: make(chan *pb.SnmpTrap, 1)}
		l.handle(nil, addr)
		l.handle(packet("public"), nil)
		l.handle(nil, nil)
		if len(l.traps) != 0 {
			t.Errorf("queued %d traps, want 0", len(l.traps))
		}
		if got := l.dropped.Load(); got != 0 {
			t.Errorf("dropped = %d, want 0", got)
		}
	})
}

// freeUDPPort reserves and immediately releases an ephemeral UDP port so the
// trap listener has a port to bind that no other test is using.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a udp port in this environment: %v", err)
	}
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		t.Fatalf("unexpected local address type %T", conn.LocalAddr())
	}
	port := uint16(udpAddr.Port) //nolint:gosec // kernel-assigned ephemeral port
	_ = conn.Close()
	return port
}

func TestTrapListenerReceivesRealTrap(t *testing.T) {
	port := freeUDPPort(t)

	l, err := startTrapListener(port, "public")
	if err != nil {
		t.Skipf("cannot bind trap port %d: %v", port, err)
	}
	defer l.Close()

	sender := &gosnmp.GoSNMP{
		Target:    "127.0.0.1",
		Port:      port,
		Transport: "udp",
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   0,
		MaxOids:   gosnmp.MaxOids,
	}
	if err := sender.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() {
		if sender.Conn != nil {
			_ = sender.Conn.Close()
		}
	}()

	if _, err := sender.SendTrap(gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123456)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
			{Name: "1.3.6.1.2.1.2.2.1.1.5", Type: gosnmp.OctetString, Value: "ether5"},
		},
	}); err != nil {
		t.Fatalf("send trap: %v", err)
	}

	select {
	case trap := <-l.Traps():
		if trap == nil {
			t.Fatal("trap channel closed before a trap arrived")
		}
		if trap.Version != 2 {
			t.Errorf("Version = %d, want 2", trap.Version)
		}
		if trap.SourceIp != "127.0.0.1" {
			t.Errorf("SourceIp = %q, want %q", trap.SourceIp, "127.0.0.1")
		}
		if trap.TrapOid != "1.3.6.1.6.3.1.1.5.3" {
			t.Errorf("TrapOid = %q, want %q", trap.TrapOid, "1.3.6.1.6.3.1.1.5.3")
		}
		if trap.UptimeTicks != 123456 {
			t.Errorf("UptimeTicks = %d, want 123456", trap.UptimeTicks)
		}
		if got := trap.Varbinds["1.3.6.1.2.1.2.2.1.1.5"]; got != "ether5" {
			t.Errorf("Varbinds = %v, want ether5 binding", trap.Varbinds)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the trap")
	}
}

func TestTrapListenerRejectsWrongCommunityOnTheWire(t *testing.T) {
	port := freeUDPPort(t)

	l, err := startTrapListener(port, "secret")
	if err != nil {
		t.Skipf("cannot bind trap port %d: %v", port, err)
	}
	defer l.Close()

	sender := &gosnmp.GoSNMP{
		Target:    "127.0.0.1",
		Port:      port,
		Transport: "udp",
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   0,
		MaxOids:   gosnmp.MaxOids,
	}
	if err := sender.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() {
		if sender.Conn != nil {
			_ = sender.Conn.Close()
		}
	}()

	if _, err := sender.SendTrap(gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.1"},
		},
	}); err != nil {
		t.Fatalf("send trap: %v", err)
	}

	select {
	case trap := <-l.Traps():
		t.Fatalf("trap with wrong community was delivered: %v", trap)
	case <-time.After(500 * time.Millisecond):
		// Expected: the community filter dropped it.
	}
}
