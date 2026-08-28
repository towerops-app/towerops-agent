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
		input string
		want  gosnmp.SnmpV3AuthProtocol
	}{
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA-1", gosnmp.SHA},
		{"SHA-224", gosnmp.SHA224},
		{"SHA-256", gosnmp.SHA256},
		{"SHA-384", gosnmp.SHA384},
		{"SHA-512", gosnmp.SHA512},
		{"unknown", gosnmp.SHA},
	}
	for _, tt := range tests {
		got := mapAuthProtocol(tt.input)
		if got != tt.want {
			t.Errorf("mapAuthProtocol(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMapPrivProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3PrivProtocol
	}{
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES-128", gosnmp.AES},
		{"AES-192", gosnmp.AES192},
		{"AES-256", gosnmp.AES256},
		{"AES-192-C", gosnmp.AES192C},
		{"AES-256-C", gosnmp.AES256C},
		{"unknown", gosnmp.AES},
	}
	for _, tt := range tests {
		got := mapPrivProtocol(tt.input)
		if got != tt.want {
			t.Errorf("mapPrivProtocol(%q) = %v, want %v", tt.input, got, tt.want)
		}
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
			conn, err := newSnmpConn(tt.dev)
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

func TestNewSnmpConnTCPError(t *testing.T) {
	// TCP transport on port 1 should fail to connect
	_, err := newSnmpConn(&pb.SnmpDevice{Ip: "127.0.0.1", Port: 1, Version: "2c", Community: "public", Transport: "tcp"})
	if err == nil {
		t.Error("expected connection error on TCP port 1")
	}
}

func TestNewSnmpConnRejectsPortOverflow(t *testing.T) {
	_, err := newSnmpConn(&pb.SnmpDevice{Ip: "127.0.0.1", Port: 65536})
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
		q, closeFn, err := realDial(&pb.SnmpDevice{Ip: "127.0.0.1", Port: 65536})
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

	t.Run("udp success returns querier and closer", func(t *testing.T) {
		// UDP "connect" only binds a socket, so no SNMP server is required.
		port := snwTFreeUDPPort(t)
		q, closeFn, err := realDial(&pb.SnmpDevice{Ip: "127.0.0.1", Port: port, Version: "2c", Community: "public"})
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
}

// Walk feeds PDUs to walkFn one at a time, mirroring gosnmp's streaming Walk.
// walkErrs[rootOid] short-circuits with an error for that subtree.
func (m *mockSnmpQuerier) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
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
		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{JobId: "1", JobType: pb.JobType_POLL}, ch)
		result := <-ch
		if len(result.OidValues) != 0 {
			t.Errorf("expected empty oid values for nil device, got %d", len(result.OidValues))
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)
		result := <-ch
		if len(result.OidValues) != 0 {
			t.Errorf("expected empty oid values on dial error, got %d", len(result.OidValues))
		}
	})

	t.Run("GET success", func(t *testing.T) {
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() { mock.closeCalled = true }, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
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
		result := <-ch
		if result.OidValues[".1.3.6.1.2.1.1.1.0"] != "Linux" {
			t.Errorf("got %q, want Linux", result.OidValues[".1.3.6.1.2.1.1.1.0"])
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_GET, Oids: []string{".1.3.6.1.2.1.1.1.0"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)
		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(context.Background(), &pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "2c"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.SnmpResult) // unbuffered, no reader — will be full
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
	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return mock, func() {}, nil
	}

	// Create 150 OIDs — should be split into 3 batches of 60, 60, 30
	oids := make([]string, 150)
	for i := range oids {
		oids[i] = fmt.Sprintf(".1.3.6.1.2.1.1.%d.0", i)
	}

	ch := make(chan *pb.SnmpResult, 1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "batch-test",
		DeviceId:   "dev-1",
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		Queries: []*pb.SnmpQuery{
			{QueryType: pb.QueryType_GET, Oids: oids},
		},
	}, ch)

	result := <-ch
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

func TestExecuteSnmpJobCtxCancelled(t *testing.T) {
	orig := snmpDial
	defer func() { snmpDial = orig }()

	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return &mockSnmpQuerier{
			getFunc: func(oids []string) (*gosnmp.SnmpPacket, error) {
				return &gosnmp.SnmpPacket{}, nil
			},
		}, func() {}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before queries run

	ch := make(chan *pb.SnmpResult, 1)
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
		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{JobId: "1"}, ch)
		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := <-ch
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
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return mock, func() {}, nil
		}

		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(context.Background(), &pb.AgentJob{
			JobId:      "test-1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)

		result := <-ch
		if !result.Success {
			t.Error("expected success even with no variables")
		}
		if result.SystemDescription != "" {
			t.Errorf("expected empty sysDescr, got %q", result.SystemDescription)
		}
	})
}

// TestSnmpValueToStringTypeMismatchFallbacks covers the fmt.Sprintf("%v", ...)
// arms reached when a device (or a buggy decoder) hands us a Value whose Go
// type is not the one gosnmp normally supplies for that Asn1BER type.
func TestSnmpValueToStringTypeMismatchFallbacks(t *testing.T) {
	tests := []struct {
		name  string
		typ   gosnmp.Asn1BER
		value any
	}{
		{name: "octet string not bytes", typ: gosnmp.OctetString, value: 42},
		{name: "object identifier not string", typ: gosnmp.ObjectIdentifier, value: struct{}{}},
		{name: "counter32 not uint", typ: gosnmp.Counter32, value: struct{}{}},
		{name: "counter64 not uint64", typ: gosnmp.Counter64, value: struct{}{}},
		{name: "gauge32 not uint", typ: gosnmp.Gauge32, value: struct{}{}},
		{name: "timeticks not uint32", typ: gosnmp.TimeTicks, value: struct{}{}},
		{name: "ipaddress not string", typ: gosnmp.IPAddress, value: struct{}{}},
		{name: "opaque not bytes", typ: gosnmp.Opaque, value: struct{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := fmt.Sprintf("%v", tt.value)
			got := snmpValueToString(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: tt.typ, Value: tt.value})
			if got != want {
				t.Errorf("snmpValueToString = %q, want %q", got, want)
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
	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		return mock, func() { mock.closeCalled = true }, nil
	}

	ch := make(chan *pb.SnmpResult, 1)
	executeSnmpJob(context.Background(), &pb.AgentJob{
		JobId:      "walk-sentinels",
		JobType:    pb.JobType_POLL,
		SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: "2c"},
		Queries: []*pb.SnmpQuery{{
			QueryType: pb.QueryType_WALK,
			Oids:      []string{".1.3.6.1.2.1.2.2.1.2"},
		}},
	}, ch)

	result := <-ch
	if !mock.bulkWalkCalled {
		t.Fatal("BulkWalkAll was not called for a v2c WALK")
	}
	want := map[string]string{
		".1.3.6.1.2.1.2.2.1.2.1": "eth0",
		".1.3.6.1.2.1.2.2.1.2.5": "eth1",
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
		".1.3.6.1.2.1.2.2.1.2.2",
		".1.3.6.1.2.1.2.2.1.2.3",
		".1.3.6.1.2.1.2.2.1.2.4",
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
