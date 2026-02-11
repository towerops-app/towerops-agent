package main

import (
	"testing"

	"github.com/gosnmp/gosnmp"
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
		{"SHA-256", gosnmp.SHA256},
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
		{"AES-256", gosnmp.AES256},
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
