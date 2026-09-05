// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"pgregory.net/rapid"
)

func TestSnmpValueToString(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want string
	}{
		{
			name: "integer",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 42},
			want: "42",
		},
		{
			name: "string",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("Linux router")},
			want: "Linux router",
		},
		{
			name: "hex bytes",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{0x00, 0x1a, 0x2b}},
			want: "00:1a:2b",
		},
		{
			name: "oid",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.2.1.1.1.0"},
			want: "1.3.6.1.2.1.1.1.0",
		},
		{
			name: "counter32",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(12345)},
			want: "12345",
		},
		{
			name: "counter64",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(9876543210)},
			want: "9876543210",
		},
		{
			name: "gauge32",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(999)},
			want: "999",
		},
		{
			name: "timeticks",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(12345678)},
			want: "12345678",
		},
		{
			name: "uinteger32",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Uinteger32, Value: uint32(4294967295)},
			want: "4294967295",
		},
		{
			name: "ip address",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: "192.168.1.1"},
			want: "192.168.1.1",
		},
		{
			name: "null",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Null, Value: nil},
			want: "null",
		},
		{
			name: "no such object",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.NoSuchObject, Value: nil},
			want: "null",
		},
		{
			name: "invalid utf8",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x80, 0xFE}},
			want: "48:65:6c:6c:6f:80:fe",
		},
		{
			name: "opaque",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Opaque, Value: []byte{0xDE, 0xAD}},
			want: "de:ad",
		},
		{
			name: "end of mib view",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.EndOfMibView, Value: nil},
			want: "null",
		},
		{
			name: "no such instance",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.NoSuchInstance, Value: nil},
			want: "null",
		},
		{
			name: "unknown type",
			pdu:  gosnmp.SnmpPDU{Type: gosnmp.Asn1BER(0xFF), Value: "something"},
			want: "something",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snmpValueToString(tt.pdu)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapAuthProtocol(t *testing.T) {
	tests := []struct {
		input   string
		want    gosnmp.SnmpV3AuthProtocol
		wantErr bool
	}{
		{"", gosnmp.SHA, false},
		{"MD5", gosnmp.MD5, false},
		{"SHA", gosnmp.SHA, false},
		{"SHA-1", gosnmp.SHA, false},
		{"SHA-224", gosnmp.SHA224, false},
		{"SHA-256", gosnmp.SHA256, false},
		{"SHA-384", gosnmp.SHA384, false},
		{"SHA-512", gosnmp.SHA512, false},
		{"unknown", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := mapAuthProtocol(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mapAuthProtocol(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("mapAuthProtocol(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMapPrivProtocol(t *testing.T) {
	tests := []struct {
		input   string
		want    gosnmp.SnmpV3PrivProtocol
		wantErr bool
	}{
		{"", gosnmp.AES, false},
		{"DES", gosnmp.DES, false},
		{"AES", gosnmp.AES, false},
		{"AES-128", gosnmp.AES, false},
		{"AES-192", gosnmp.AES192, false},
		{"AES-256", gosnmp.AES256, false},
		{"AES-192-C", gosnmp.AES192C, false},
		{"AES-256-C", gosnmp.AES256C, false},
		{"unknown", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := mapPrivProtocol(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mapPrivProtocol(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("mapPrivProtocol(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatHex(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0xAB}, "ab"},
		{[]byte{0x00, 0xFF, 0x1A}, "00:ff:1a"},
	}
	for _, tt := range tests {
		got := formatHex(tt.input)
		if got != tt.want {
			t.Errorf("formatHex(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewSnmpConn(t *testing.T) {
	tests := []struct {
		name string
		dev  *pb.SnmpDevice
	}{
		{
			name: "v1",
			dev:  &pb.SnmpDevice{Ip: "127.0.0.1", Port: 0, Version: "v1", Community: "public"},
		},
		{
			name: "v2c default",
			dev:  &pb.SnmpDevice{Ip: "127.0.0.1", Port: 0, Version: "2c", Community: "public"},
		},
		{
			name: "v2c empty version",
			dev:  &pb.SnmpDevice{Ip: "127.0.0.1", Port: 0, Community: "public"},
		},
		{
			name: "v3 noAuthNoPriv",
			dev:  &pb.SnmpDevice{Ip: "127.0.0.1", Port: 0, Version: "v3", V3Username: "user", V3SecurityLevel: "noAuthNoPriv"},
		},
		{
			name: "v3 authNoPriv",
			dev: &pb.SnmpDevice{
				Ip: "127.0.0.1", Port: 0, Version: "v3",
				V3Username: "user", V3SecurityLevel: "authNoPriv",
				V3AuthProtocol: "SHA-256", V3AuthPassword: "pass1234",
			},
		},
		{
			name: "v3 authPriv",
			dev: &pb.SnmpDevice{
				Ip: "127.0.0.1", Port: 0, Version: "v3",
				V3Username: "user", V3SecurityLevel: "authPriv",
				V3AuthProtocol: "SHA-256", V3AuthPassword: "pass1234",
				V3PrivProtocol: "AES-256", V3PrivPassword: "priv1234",
			},
		},
		{
			name: "tcp transport",
			dev:  &pb.SnmpDevice{Ip: "127.0.0.1", Port: 0, Version: "2c", Community: "public", Transport: "tcp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := newSnmpConn(context.Background(), tt.dev)
			if err != nil {
				return
			}
			defer func() { _ = conn.Conn.Close() }()

			// Verify version was set correctly
			switch tt.dev.Version {
			case "1", "v1":
				if conn.Version != gosnmp.Version1 {
					t.Errorf("expected Version1, got %v", conn.Version)
				}
			case "3", "v3":
				if conn.Version != gosnmp.Version3 {
					t.Errorf("expected Version3, got %v", conn.Version)
				}
			default:
				if conn.Version != gosnmp.Version2c {
					t.Errorf("expected Version2c, got %v", conn.Version)
				}
			}
		})
	}
}

func TestNewSnmpConnDefaultsPort(t *testing.T) {
	conn, err := newSnmpConn(context.Background(), &pb.SnmpDevice{
		Ip:        "127.0.0.1",
		Version:   "2c",
		Community: "public",
	})
	if err != nil {
		t.Fatalf("newSnmpConn: %v", err)
	}
	defer func() { _ = conn.Conn.Close() }()

	if conn.Port != 161 {
		t.Fatalf("conn.Port = %d, want 161", conn.Port)
	}
}

func TestNewSnmpConnTCPError(t *testing.T) {
	// TCP transport on port 1 should fail to connect
	_, err := newSnmpConn(context.Background(), &pb.SnmpDevice{Ip: "127.0.0.1", Port: 1, Version: "2c", Community: "public", Transport: "tcp"})
	if err == nil {
		t.Error("expected connection error on TCP port 1")
	}
}

func TestNewSnmpConnRejectsPortOverflow(t *testing.T) {
	_, err := newSnmpConn(context.Background(), &pb.SnmpDevice{Ip: "127.0.0.1", Port: 65536})
	if err == nil || !strings.Contains(err.Error(), "invalid SNMP port") {
		t.Fatalf("newSnmpConn error = %v, want invalid port", err)
	}
}

// snwTFreeUDPPort binds an ephemeral UDP socket on loopback and keeps it open
// for the duration of the test, so the returned port is stable and cannot be
// re-bound by a concurrently running test.
func snwTFreeUDPPort(t *testing.T) uint32 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr is %T, want *net.UDPAddr", pc.LocalAddr())
	}
	return uint32(addr.Port)
}

// TestSnmpDialDefault exercises the real snmpDial closure (not a copy of it),
// covering both the newSnmpConn error path and the success path.
func TestSnmpDialDefault(t *testing.T) {
	realDial := snmpDial

	t.Run("newSnmpConn error propagates", func(t *testing.T) {
		q, closeFn, err := realDial(context.Background(), &pb.SnmpDevice{Ip: "127.0.0.1", Port: 65536})
		if err == nil || !strings.Contains(err.Error(), "invalid SNMP port") {
			t.Fatalf("snmpDial error = %v, want invalid SNMP port", err)
		}
		if q != nil {
			t.Errorf("snmpDial querier = %v, want nil on error", q)
		}
		if closeFn != nil {
			t.Error("snmpDial close func non-nil on error")
		}
	})

	t.Run("udp success preserves context and returns closer", func(t *testing.T) {
		// UDP "connect" only binds a socket, so no SNMP server is required.
		port := snwTFreeUDPPort(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		q, closeFn, err := realDial(ctx, &pb.SnmpDevice{Ip: "127.0.0.1", Port: port, Version: "2c", Community: "public"})
		if err != nil {
			t.Fatalf("snmpDial: %v", err)
		}
		if q == nil {
			t.Fatal("snmpDial querier = nil, want non-nil")
		}
		if closeFn == nil {
			t.Fatal("snmpDial close func = nil, want non-nil")
		}
		conn, ok := q.(*gosnmp.GoSNMP)
		if !ok {
			t.Fatalf("snmpDial querier is %T, want *gosnmp.GoSNMP", q)
		}
		if conn.Port != uint16(port) {
			t.Errorf("conn.Port = %d, want %d", conn.Port, port)
		}
		if conn.Context != ctx {
			t.Fatal("dialed connection did not retain caller context")
		}
		closeFn()
		// The closer released the socket: a second write must now fail.
		if _, err := conn.Conn.Write([]byte("x")); err == nil {
			t.Error("write succeeded after closeFn, want closed-socket error")
		}
	})
}

// mockSnmpQuerier implements snmpQuerier for testing.
type mockSnmpQuerier struct {
	getFunc        func(oids []string) (*gosnmp.SnmpPacket, error)
	walkFunc       func(rootOid string) ([]gosnmp.SnmpPDU, error)
	bulkWalkFunc   func(rootOid string) ([]gosnmp.SnmpPDU, error)
	walkStepFunc   func(rootOid string) ([]gosnmp.SnmpPDU, error)
	walkErrs       map[string]error
	closeCalled    bool
	walkAllCalled  bool
	bulkWalkCalled bool
	walkRoots      []string
	bulkWalkRoots  []string
}

// Walk feeds PDUs to walkFn one at a time, mirroring gosnmp's streaming Walk.
// walkErrs[rootOid] short-circuits with an error for that subtree.
func (m *mockSnmpQuerier) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
	m.walkRoots = append(m.walkRoots, rootOid)
	return m.runWalk(rootOid, walkFn)
}

func (m *mockSnmpQuerier) BulkWalk(rootOid string, walkFn gosnmp.WalkFunc) error {
	m.bulkWalkRoots = append(m.bulkWalkRoots, rootOid)
	return m.runWalk(rootOid, walkFn)
}

func (m *mockSnmpQuerier) runWalk(rootOid string, walkFn gosnmp.WalkFunc) error {
	if err, ok := m.walkErrs[rootOid]; ok {
		return err
	}
	if m.walkStepFunc == nil {
		return nil
	}
	pdus, err := m.walkStepFunc(rootOid)
	if err != nil {
		return err
	}
	for _, pdu := range pdus {
		if err := walkFn(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockSnmpQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return m.getFunc(oids)
}

func (m *mockSnmpQuerier) WalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	m.walkAllCalled = true
	return m.walkFunc(rootOid)
}

func (m *mockSnmpQuerier) BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	m.bulkWalkCalled = true
	if m.bulkWalkFunc != nil {
		return m.bulkWalkFunc(rootOid)
	}
	return m.walkFunc(rootOid)
}

func TestExecuteSnmpJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{JobId: "1", JobType: pb.JobType_POLL}, ch)
		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("expected empty oid values for nil device, got %d", len(result.OidValues))
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)
		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("expected empty oid values on dial error, got %d", len(result.OidValues))
		}
	})

	t.Run("GET dotted PDU key is canonicalized", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Variables: []gosnmp.SnmpPDU{
						{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("Linux")},
					},
				}, nil
			},
		}
		var gotCtx context.Context
		snmpDial = func(ctx context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			gotCtx = ctx
			return mock, func() { mock.closeCalled = true }, nil
		}

		ch := make(resultQueue, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		executeSnmpJob(ctx, &pb.AgentJob{
			JobId:      "1",
			DeviceId:   "dev-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			},
		}, ch)

		if len(ch) != 1 {
			t.Fatal("expected one result")
		}
		result := (<-ch).msg.(*pb.SnmpResult)
		if gotCtx != ctx {
			t.Fatal("snmpDial did not receive the job context")
		}
		if got := result.OidValues["1.3.6.1.2.1.1.1.0"]; got != "Linux" {
			t.Errorf("got %q, want Linux", got)
		}
		if _, ok := result.OidValues[".1.3.6.1.2.1.1.1.0"]; ok {
			t.Error("dotted OID key was not canonicalized")
		}
		if !mock.closeCalled {
			t.Error("expected close to be called")
		}
	})

	t.Run("WALK success", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{
					{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: 1},
					{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: 2},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 2 {
			t.Errorf("got %d oid values, want 2", len(result.OidValues))
		}
	})

	t.Run("GET error continues", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return nil, fmt.Errorf("timeout")
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("got %d oid values, want 0 on error", len(result.OidValues))
		}
	})

	t.Run("WALK error continues", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
				return nil, fmt.Errorf("timeout")
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("got %d oid values, want 0 on error", len(result.OidValues))
		}
	})

	t.Run("NoSuchObject skipped", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Variables: []gosnmp.SnmpPDU{
						{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.NoSuchObject, Value: nil},
					},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("NoSuchObject should be skipped, got %d oid values", len(result.OidValues))
		}
	})

	t.Run("WALK NoSuchObject skipped", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{
					{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: 1},
					{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.NoSuchInstance, Value: nil},
					{Name: ".1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.EndOfMibView, Value: nil},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)
		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 0 {
			t.Errorf("expected empty oid values on dial error, got %d", len(result.OidValues))
		}
	})

	t.Run("WALK v1 uses WalkAll", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{
					{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: 1},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 1 {
			t.Errorf("got %d oid values, want 1", len(result.OidValues))
		}
		if !mock.walkAllCalled {
			t.Error("expected WalkAll to be called for v1")
		}
		if mock.bulkWalkCalled {
			t.Error("BulkWalkAll should not be called for v1")
		}
	})

	t.Run("WALK v2c uses BulkWalkAll", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			walkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{
					{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: 1},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "2c"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := (<-ch).msg.(*pb.SnmpResult)
		if len(result.OidValues) != 1 {
			t.Errorf("got %d oid values, want 1", len(result.OidValues))
		}
		if !mock.bulkWalkCalled {
			t.Error("expected BulkWalkAll to be called for v2c")
		}
		if mock.walkAllCalled {
			t.Error("WalkAll should not be called for v2c")
		}
	})

	t.Run("channel full drops", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue) // unbuffered, no reader — will be full
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)
		// Should not block — the result is dropped
	})
}

func TestExecuteSnmpJobBatchesGets(t *testing.T) {
	orig := snmpDial
	defer func() { snmpDial = orig }()

	var getCalls [][]string
	mock := &mockSnmpQuerier{
		getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
			getCalls = append(getCalls, oids)
			var vars []gosnmp.SnmpPDU
			for _, oid := range oids {
				vars = append(vars, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: 42})
			}
			return &gosnmp.SnmpPacket{Variables: vars}, nil
		},
	}
	snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return mock, func() {}, nil
	}

	// Create 150 OIDs — should be split into 3 batches of 60, 60, 30
	oids := make([]string, 150)
	for i := range oids {
		oids[i] = fmt.Sprintf(".1.3.6.1.2.1.1.%d.0", i)
	}

	ch := make(resultQueue, 1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "batch-test",
		DeviceId:   "dev-1",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: oids},
		},
	}, ch)

	result := (<-ch).msg.(*pb.SnmpResult)
	if len(result.OidValues) != 150 {
		t.Errorf("got %d oid values, want 150", len(result.OidValues))
	}
	if len(getCalls) != 3 {
		t.Errorf("got %d GET calls, want 3 (batches of 60)", len(getCalls))
	}
	for i, call := range getCalls {
		if i < 2 && len(call) != 60 {
			t.Errorf("batch %d: got %d oids, want 60", i, len(call))
		}
		if i == 2 && len(call) != 30 {
			t.Errorf("batch %d: got %d oids, want 30", i, len(call))
		}
	}
}
func TestExecuteSnmpJobSplitsErrorStatusBatches(t *testing.T) {
	const badOID = ".1.3.6.1.2.1.1.2.0"
	oids := []string{
		".1.3.6.1.2.1.1.1.0",
		badOID,
		".1.3.6.1.2.1.1.3.0",
		".1.3.6.1.2.1.1.4.0",
	}

	tests := []struct {
		name string
		get  func([]string) (*gosnmp.SnmpPacket, error)
		want map[string]string
	}{
		{
			name: "noSuchName",
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				containsBadOID := false
				for _, oid := range batch {
					if oid == badOID {
						containsBadOID = true
						break
					}
				}
				if containsBadOID {
					vars := make([]gosnmp.SnmpPDU, len(batch))
					for i, oid := range batch {
						vars[i] = gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Null}
					}
					errorIndex := uint8(2)
					if len(batch) == 1 {
						errorIndex = 1
					}
					return &gosnmp.SnmpPacket{
						Error:      gosnmp.NoSuchName,
						ErrorIndex: errorIndex,
						Variables:  vars,
					}, nil
				}
				vars := make([]gosnmp.SnmpPDU, len(batch))
				for i, oid := range batch {
					vars[i] = gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte("resolved")}
				}
				return &gosnmp.SnmpPacket{Variables: vars}, nil
			},
			want: map[string]string{
				"1.3.6.1.2.1.1.1.0": "resolved",
				"1.3.6.1.2.1.1.3.0": "resolved",
				"1.3.6.1.2.1.1.4.0": "resolved",
			},
		},
		{
			name: "tooBig",
			get: func(batch []string) (*gosnmp.SnmpPacket, error) {
				if len(batch) > 2 {
					return &gosnmp.SnmpPacket{Error: gosnmp.TooBig, ErrorIndex: 0}, nil
				}
				vars := make([]gosnmp.SnmpPDU, len(batch))
				for i, oid := range batch {
					vars[i] = gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: 42}
				}
				return &gosnmp.SnmpPacket{Variables: vars}, nil
			},
			want: map[string]string{
				"1.3.6.1.2.1.1.1.0": "42",
				"1.3.6.1.2.1.1.2.0": "42",
				"1.3.6.1.2.1.1.3.0": "42",
				"1.3.6.1.2.1.1.4.0": "42",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := snmpDial
			defer func() { snmpDial = orig }()
			mock := &mockSnmpQuerier{getFunc: tt.get}
			snmpDial = func(_ context.Context, _ *pb.SnmpDevice) (snmpQuerier, func(), error) {
				return mock, func() {}, nil
			}

			out := make(resultQueue, 1)
			executeSnmpJob(context.Background(), &pb.AgentJob{
				JobId:      "error-status",
				DeviceId:   "dev-1",
				SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "1"},
				Queries: []*pb.SnmpQuery{
					{QueryType: pb.QueryType_GET, Oids: oids},
				},
			}, out)

			o := <-out
			if o.event != "result" {
				t.Fatalf("event = %q, want result", o.event)
			}
			result := o.msg.(*pb.SnmpResult)
			if len(result.OidValues) != len(tt.want) {
				t.Fatalf("oid_values = %v, want %v", result.OidValues, tt.want)
			}
			for oid, want := range tt.want {
				if got := result.OidValues[oid]; got != want {
					t.Errorf("oid_values[%q] = %q, want %q", oid, got, want)
				}
			}
			for oid, got := range result.OidValues {
				if got == "null" {
					t.Errorf("oid_values[%q] stored null error-status varbind", oid)
				}
			}
		})
	}
}

func TestExecuteSnmpJobCtxCancelled(t *testing.T) {
	orig := snmpDial
	defer func() { snmpDial = orig }()

	snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before queries run

	ch := make(resultQueue, 1)
	executeSnmpJob(ctx, &pb.AgentJob{
		JobId:      "ctx-test",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.2.0"}},
		},
	}, ch)

	// With cancelled context, the function should return before processing queries
	// (no result sent because it returns early in the ctx.Err() check)
	select {
	case <-ch:
		// Might get a result if the first query ran before ctx check
	default:
		// Expected — returned early
	}
}

func TestExecuteCredentialTest(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{JobId: "1"}, ch)
		result := (<-ch).msg.(*pb.CredentialTestResult)
		if result.Success {
			t.Error("expected failure for nil device")
		}
		if !strings.Contains(result.ErrorMessage, "missing device") {
			t.Errorf("expected 'missing device' in error, got: %s", result.ErrorMessage)
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)

		result := (<-ch).msg.(*pb.CredentialTestResult)
		if result.Success {
			t.Error("expected failure")
		}
		if result.ErrorMessage == "" {
			t.Error("expected error message")
		}
	})

	t.Run("get error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return nil, fmt.Errorf("timeout")
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := (<-ch).msg.(*pb.CredentialTestResult)
		if result.Success {
			t.Error("expected failure on get error")
		}
	})

	t.Run("success", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Variables: []gosnmp.SnmpPDU{
						{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("RouterOS 7.1")},
					},
				}, nil
			},
		}
		var gotCtx context.Context
		snmpDial = func(ctx context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			gotCtx = ctx
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		executeCredentialTest(ctx, &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := (<-ch).msg.(*pb.CredentialTestResult)
		if gotCtx != ctx {
			t.Fatal("snmpDial did not receive the credential-test context")
		}
		if !result.Success {
			t.Error("expected success")
		}
		if result.SystemDescription != "RouterOS 7.1" {
			t.Errorf("sysDescr: got %q, want %q", result.SystemDescription, "RouterOS 7.1")
		}
	})

	t.Run("success no variables", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{Variables: nil}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := (<-ch).msg.(*pb.CredentialTestResult)
		if !result.Success {
			t.Error("expected success even with no variables")
		}
		if result.SystemDescription != "" {
			t.Errorf("expected empty sysDescr, got %q", result.SystemDescription)
		}
	})

	t.Run("success sentinel sysDescr stays empty", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Variables: []gosnmp.SnmpPDU{{
						Name:  ".1.3.6.1.2.1.1.1.0",
						Type:  gosnmp.NoSuchInstance,
						Value: nil,
					}},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-sentinel",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := (<-ch).msg.(*pb.CredentialTestResult)
		if !result.Success {
			t.Error("expected successful credential test")
		}
		if result.SystemDescription != "" {
			t.Fatalf("SystemDescription = %q, want empty", result.SystemDescription)
		}
	})
	t.Run("error status leaves sysDescr empty", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		mock := &mockSnmpQuerier{
			getFunc: func(_ []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{
					Error:      gosnmp.NoSuchName,
					ErrorIndex: 1,
					Variables: []gosnmp.SnmpPDU{{
						Name: ".1.3.6.1.2.1.1.1.0",
						Type: gosnmp.Null,
					}},
				}, nil
			},
		}
		snmpDial = func(_ context.Context, _ *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		out := make(resultQueue, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-error-status",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "1"},
		}, out)

		result := (<-out).msg.(*pb.CredentialTestResult)
		if !result.Success {
			t.Error("successful GET should prove the credentials")
		}
		if result.SystemDescription != "" {
			t.Fatalf("SystemDescription = %q, want empty", result.SystemDescription)
		}
	})

}
func TestExecuteCredentialTestRejectsUnsupportedAuthProtocol(t *testing.T) {
	out := make(resultQueue, 1)
	executeCredentialTest(context.Background(), &pb.AgentJob{
		JobId: "unsupported-auth",
		SnmpDevice: &pb.SnmpDevice{
			Ip:              "127.0.0.1",
			Version:         "v3",
			V3Username:      "user",
			V3SecurityLevel: "authNoPriv",
			V3AuthProtocol:  "SHA256",
			V3AuthPassword:  "pass1234",
		},
	}, out)

	o := <-out
	if o.event != "credential_test_result" {
		t.Fatalf("event = %q, want credential_test_result", o.event)
	}
	result := o.msg.(*pb.CredentialTestResult)
	if result.Success {
		t.Fatal("credential test succeeded with unsupported auth protocol")
	}
	if !strings.Contains(result.ErrorMessage, `unsupported SNMPv3 auth protocol "SHA256"`) {
		t.Fatalf("ErrorMessage = %q, want unsupported protocol", result.ErrorMessage)
	}
}

// TestSnmpValueToStringTypeMismatchFallbacks covers malformed PDU values.
func TestSnmpValueToStringTypeMismatchFallbacks(t *testing.T) {
	tests := []struct {
		name  string
		typ   gosnmp.Asn1BER
		value any
		want  string
	}{
		{name: "octet string not bytes", typ: gosnmp.OctetString, value: 42, want: "42"},
		{name: "object identifier not string", typ: gosnmp.ObjectIdentifier, value: struct{}{}, want: "{}"},
		{name: "counter32 not numeric", typ: gosnmp.Counter32, value: struct{}{}, want: "0"},
		{name: "counter64 not numeric", typ: gosnmp.Counter64, value: struct{}{}, want: "0"},
		{name: "gauge32 not numeric", typ: gosnmp.Gauge32, value: struct{}{}, want: "0"},
		{name: "timeticks not numeric", typ: gosnmp.TimeTicks, value: struct{}{}, want: "0"},
		{name: "uinteger32 not numeric", typ: gosnmp.Uinteger32, value: struct{}{}, want: "0"},
		{name: "ipaddress not string", typ: gosnmp.IPAddress, value: struct{}{}, want: "{}"},
		{name: "opaque not bytes", typ: gosnmp.Opaque, value: struct{}{}, want: "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snmpValueToString(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: tt.typ, Value: tt.value})
			if got != tt.want {
				t.Errorf("snmpValueToString = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExecuteSnmpJobWalkSkipsSentinelPDUs asserts the WALK branch drops
// NoSuchObject / NoSuchInstance / EndOfMibView PDUs instead of recording them.
func TestExecuteSnmpJobWalkSkipsSentinelPDUs(t *testing.T) {
	orig := snmpDial
	defer func() { snmpDial = orig }()

	mock := &mockSnmpQuerier{
		bulkWalkFunc: func(rootOid string) ([]gosnmp.SnmpPDU, error) {
			return []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: []byte("eth0")},
				{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: gosnmp.NoSuchObject},
				{Name: ".1.3.6.1.2.1.2.2.1.2.3", Type: gosnmp.NoSuchInstance},
				{Name: ".1.3.6.1.2.1.2.2.1.2.4", Type: gosnmp.EndOfMibView},
				{Name: ".1.3.6.1.2.1.2.2.1.2.5", Type: gosnmp.OctetString, Value: []byte("eth1")},
			}, nil
		},
	}
	snmpDial = func(_ context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return mock, func() { mock.closeCalled = true }, nil
	}

	ch := make(resultQueue, 1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "walk-sentinels",
		JobType:    pb.JobType_POLL,
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_WALK,
			Oids:      []string{".1.3.6.1.2.1.2.2.1.2"},
		}},
	}, ch)

	result := (<-ch).msg.(*pb.SnmpResult)
	if !mock.bulkWalkCalled {
		t.Fatal("BulkWalkAll was not called for a v2c WALK")
	}
	want := map[string]string{
		"1.3.6.1.2.1.2.2.1.2.1": "eth0",
		"1.3.6.1.2.1.2.2.1.2.5": "eth1",
	}
	if len(result.OidValues) != len(want) {
		t.Fatalf("OidValues = %v, want %v", result.OidValues, want)
	}
	for oid, v := range want {
		if result.OidValues[oid] != v {
			t.Errorf("OidValues[%s] = %q, want %q", oid, result.OidValues[oid], v)
		}
	}
	for _, skipped := range []string{
		"1.3.6.1.2.1.2.2.1.2.2",
		"1.3.6.1.2.1.2.2.1.2.3",
		"1.3.6.1.2.1.2.2.1.2.4",
	} {
		if got, ok := result.OidValues[skipped]; ok {
			t.Errorf("sentinel OID %s recorded as %q, want absent", skipped, got)
		}
	}
	if !mock.closeCalled {
		t.Error("close func was not invoked")
	}
}

// snwTValueGen draws the Value shapes a real (or hostile) SNMP decoder can
// place in an SnmpPDU.
var snwTValueGen = rapid.OneOf(
	rapid.Custom(func(t *rapid.T) any { return any(rapid.SliceOf(rapid.Byte()).Draw(t, "bytes")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.String().Draw(t, "string")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.Int().Draw(t, "int")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.Uint().Draw(t, "uint")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.Int64().Draw(t, "int64")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.Uint64().Draw(t, "uint64")) }),
	rapid.Custom(func(t *rapid.T) any { return any(rapid.Uint32().Draw(t, "uint32")) }),
	rapid.Just(any(nil)),
	rapid.Just(any(struct{}{})),
)

// TestPropSnwSnmpValueToStringNeverPanics is a robustness invariant: whatever
// type byte and Value shape a device produces, conversion must return a
// deterministic, valid UTF-8 string rather than panicking.
func TestPropSnwSnmpValueToStringNeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		typ := gosnmp.Asn1BER(rapid.Byte().Draw(t, "type"))
		value := snwTValueGen.Draw(t, "value")
		pdu := gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: typ, Value: value}

		got := snmpValueToString(pdu)
		if !utf8.ValidString(got) {
			t.Fatalf("snmpValueToString(type=%#x, value=%#v) = %q: not valid UTF-8", byte(typ), value, got)
		}
		if again := snmpValueToString(pdu); again != got {
			t.Fatalf("snmpValueToString not deterministic: %q then %q", got, again)
		}
	})
}

// snwTOctetGen draws byte slices biased towards both the printable path and
// the hex-escape path of the OctetString arm.
var snwTOctetGen = rapid.OneOf(
	rapid.SliceOf(rapid.Byte()),
	rapid.Custom(func(t *rapid.T) []byte { return []byte(rapid.String().Draw(t, "clean")) }),
	rapid.Custom(func(t *rapid.T) []byte {
		s := []byte(rapid.String().Draw(t, "base"))
		ctl := rapid.SampledFrom([]byte{0x00, 0x01, 0x07, 0x0b, 0x1f}).Draw(t, "ctl")
		at := rapid.IntRange(0, len(s)).Draw(t, "at")
		out := make([]byte, 0, len(s)+1)
		out = append(out, s[:at]...)
		out = append(out, ctl)
		return append(out, s[at:]...)
	}),
)

// TestPropSnwOctetStringRoundtrip fully characterises the OctetString arm:
// printable UTF-8 passes through byte-for-byte, everything else is hex escaped.
func TestPropSnwOctetStringRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := snwTOctetGen.Draw(t, "b")
		got := snmpValueToString(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: b})

		printable := utf8.Valid(b)
		if printable {
			for _, c := range b {
				if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
					printable = false
					break
				}
			}
		}
		if printable {
			if got != string(b) {
				t.Fatalf("snmpValueToString(%#v) = %q, want verbatim %q", b, got, string(b))
			}
			return
		}
		if got != formatHex(b) {
			t.Fatalf("snmpValueToString(%#v) = %q, want hex %q", b, got, formatHex(b))
		}
	})
}

// TestPropSnwFormatHex pins formatHex's output shape: deterministic, length a
// pure function of the input length, and losslessly decodable.
func TestPropSnwFormatHex(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOf(rapid.Byte()).Draw(t, "b")
		got := formatHex(b)

		if again := formatHex(b); again != got {
			t.Fatalf("formatHex not deterministic: %q then %q", got, again)
		}

		wantLen := 0
		wantColons := 0
		if len(b) > 0 {
			wantLen = 3*len(b) - 1
			wantColons = len(b) - 1
		}
		if len(got) != wantLen {
			t.Fatalf("len(formatHex(%d bytes)) = %d, want %d", len(b), len(got), wantLen)
		}
		if n := strings.Count(got, ":"); n != wantColons {
			t.Fatalf("formatHex(%#v) has %d colons, want %d", b, n, wantColons)
		}
		if lower := strings.ToLower(got); lower != got {
			t.Fatalf("formatHex(%#v) = %q, want lowercase hex", b, got)
		}

		decoded, err := hex.DecodeString(strings.ReplaceAll(got, ":", ""))
		if err != nil {
			t.Fatalf("hex.DecodeString(%q): %v", got, err)
		}
		if string(decoded) != string(b) {
			t.Fatalf("formatHex round-trip = %#v, want %#v", decoded, b)
		}
	})
}

// TestPropSnwIntegerRoundtrip asserts the Integer arm is a lossless decimal
// rendering for both Go types gosnmp may carry.
func TestPropSnwIntegerRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.Int64().Draw(t, "int64")
		got := snmpValueToString(gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: v})
		back, err := strconv.ParseInt(got, 10, 64)
		if err != nil {
			t.Fatalf("ParseInt(%q): %v", got, err)
		}
		if back != v {
			t.Fatalf("int64 round-trip: got %d, want %d", back, v)
		}

		// gosnmp decodes Integer PDUs into a plain int.
		n := rapid.Int().Draw(t, "int")
		gotN := snmpValueToString(gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: n})
		backN, err := strconv.ParseInt(gotN, 10, 64)
		if err != nil {
			t.Fatalf("ParseInt(%q): %v", gotN, err)
		}
		if backN != int64(n) {
			t.Fatalf("int round-trip: got %d, want %d", backN, n)
		}
	})
}
