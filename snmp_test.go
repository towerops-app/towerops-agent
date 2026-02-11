package main

import (
	"fmt"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
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

func TestSnmpDialDefault(t *testing.T) {
	// Test the default snmpDial function variable (wraps newSnmpConn)
	origDial := snmpDial
	defer func() { snmpDial = origDial }()

	// Reset to default behavior
	snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
		conn, err := newSnmpConn(dev)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { _ = conn.Conn.Close() }, nil
	}

	q, closeFn, err := snmpDial(&pb.SnmpDevice{Ip: "127.0.0.1", Port: 16100, Version: "2c", Community: "public"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closeFn()
	if q == nil {
		t.Error("expected non-nil querier")
	}
}

// mockSnmpQuerier implements snmpQuerier for testing.
type mockSnmpQuerier struct {
	getFunc     func(oids []string) (*gosnmp.SnmpPacket, error)
	walkFunc    func(rootOid string) ([]gosnmp.SnmpPDU, error)
	closeCalled bool
}

func (m *mockSnmpQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return m.getFunc(oids)
}

func (m *mockSnmpQuerier) BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error) {
	return m.walkFunc(rootOid)
}

func TestExecuteSnmpJob(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(&pb.AgentJob{JobId: "1"}, ch)
		if len(ch) != 0 {
			t.Error("expected no result for nil device")
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(chan *pb.SnmpResult, 1)
		executeSnmpJob(&pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Port: 161},
		}, ch)
		if len(ch) != 0 {
			t.Error("expected no result on dial error")
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
		executeSnmpJob(&pb.AgentJob{
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
		executeSnmpJob(&pb.AgentJob{
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
		executeSnmpJob(&pb.AgentJob{
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
		executeSnmpJob(&pb.AgentJob{
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
		executeSnmpJob(&pb.AgentJob{
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
		executeSnmpJob(&pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
			Queries: []*pb.SnmpQuery{
				{QueryType: pb.QueryType_WALK, Oids: []string{".1.3.6.1.2.1.2.2.1.1"}},
			},
		}, ch)

		result := <-ch
		if len(result.OidValues) != 1 {
			t.Errorf("expected 1 value (others skipped), got %d", len(result.OidValues))
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
		executeSnmpJob(&pb.AgentJob{
			JobId:      "1",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, ch)
		// Should not block — the result is dropped
	})
}

func TestExecuteCredentialTest(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(&pb.AgentJob{JobId: "1"}, ch)
		if len(ch) != 0 {
			t.Error("expected no result for nil device")
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, fmt.Errorf("connection refused")
		}

		ch := make(chan *pb.CredentialTestResult, 1)
		executeCredentialTest(&pb.AgentJob{
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
		executeCredentialTest(&pb.AgentJob{
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
		executeCredentialTest(&pb.AgentJob{
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
		executeCredentialTest(&pb.AgentJob{
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
