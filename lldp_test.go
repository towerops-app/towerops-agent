// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"pgregory.net/rapid"
)

// lldpTPdu builds an OctetString PDU so snmpValueToString yields value verbatim.
func lldpTPdu(name, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: []byte(value)}
}

// lldpTPacket wraps variables in an SNMP packet for mockSnmpQuerier.getFunc.
func lldpTPacket(pdus ...gosnmp.SnmpPDU) *gosnmp.SnmpPacket {
	return &gosnmp.SnmpPacket{Variables: pdus}
}

// lldpTSysNameOK returns a getFunc yielding name for oidLocSysName.
func lldpTSysNameOK(name string) func([]string) (*gosnmp.SnmpPacket, error) {
	return func(oids []string) (*gosnmp.SnmpPacket, error) {
		if len(oids) != 1 || oids[0] != oidLocSysName {
			return nil, fmt.Errorf("unexpected get oids %v", oids)
		}
		return lldpTPacket(lldpTPdu("."+oidLocSysName, name)), nil
	}
}

// lldpTWalk builds a walkStepFunc from a root-OID -> PDUs table.
func lldpTWalk(table map[string][]gosnmp.SnmpPDU) func(string) ([]gosnmp.SnmpPDU, error) {
	return func(rootOid string) ([]gosnmp.SnmpPDU, error) {
		return table[rootOid], nil
	}
}

// lldpTMgmtOid builds a management-address OID with the given index parts.
func lldpTMgmtOid(leadingDot bool, key string, subtype string, addrLen int, octets []int) string {
	parts := []string{key, subtype, strconv.Itoa(addrLen)}
	for _, o := range octets {
		parts = append(parts, strconv.Itoa(o))
	}
	oid := oidRemManAddr + "." + strings.Join(parts, ".")
	if leadingDot {
		return "." + oid
	}
	return oid
}

func TestSortedLldpKeys(t *testing.T) {
	got := sortedLldpKeys(map[string]string{"3.2.1": "c", "1.2.1": "a", "2.2.1": "b"})
	want := []string{"1.2.1", "2.2.1", "3.2.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("sortedLldpKeys = %v, want %v", got, want)
	}
}

func TestLldpTExtractSuffix(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		base string
		want string
	}{
		{"leading dot", "." + oidRemSysName + ".0.5.1", oidRemSysName, "0.5.1"},
		{"no leading dot", oidRemSysName + ".0.5.1", oidRemSysName, "0.5.1"},
		{"non matching", ".1.2.3.4", oidRemSysName, ""},
		{"base without trailing dot", oidRemSysName, oidRemSysName, ""},
		{"different base", "." + oidRemPortId + ".0.5.1", oidRemSysName, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSuffix(tt.oid, tt.base); got != tt.want {
				t.Fatalf("extractSuffix(%q, %q) = %q, want %q", tt.oid, tt.base, got, tt.want)
			}
		})
	}
}

func TestLldpTParseRemoteKey(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		want string
	}{
		{"empty suffix", ".9.9.9", ""},
		{"one part", "." + oidRemSysName + ".7", ""},
		{"two parts", "." + oidRemSysName + ".7.8", ""},
		{"three parts", "." + oidRemSysName + ".0.5.1", "0.5.1"},
		{"four parts keeps first three", oidRemSysName + ".0.5.1.99", "0.5.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRemoteKey(tt.oid, oidRemSysName); got != tt.want {
				t.Fatalf("parseRemoteKey(%q) = %q, want %q", tt.oid, got, tt.want)
			}
		})
	}
}

func TestLldpTParseMgmtAddr(t *testing.T) {
	tests := []struct {
		name    string
		oid     string
		wantKey string
		wantIP  string
	}{
		{
			name: "non matching oid",
			oid:  ".1.3.6.1.2.1.1.1.0",
		},
		{
			name: "too few parts",
			oid:  "." + oidRemManAddr + ".0.5.1.1.4.10.0",
		},
		{
			name:    "ipv4",
			oid:     lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 0, 0, 7}),
			wantKey: "0.5.1",
			wantIP:  "10.0.0.7",
		},
		{
			name:    "ipv4 no leading dot",
			oid:     lldpTMgmtOid(false, "0.6.2", "1", 4, []int{192, 168, 1, 1}),
			wantKey: "0.6.2",
			wantIP:  "192.168.1.1",
		},
		{
			name:    "ipv4 invalid octet fails ParseIP",
			oid:     lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 0, 0, 999}),
			wantKey: "0.5.1",
		},
		{
			name:    "ipv4 address length mismatch",
			oid:     lldpTMgmtOid(true, "0.5.1", "1", 16, []int{10, 0, 0, 7}),
			wantKey: "0.5.1",
		},
		{
			name:    "non-numeric address length",
			oid:     "." + oidRemManAddr + ".0.5.1.1.xx.10.0.0.7",
			wantKey: "0.5.1",
		},
		{
			name:    "ipv6 truncated",
			oid:     lldpTMgmtOid(true, "0.5.1", "2", 16, []int{32, 1, 13, 184}),
			wantKey: "0.5.1",
		},
		{
			name: "ipv6",
			oid: lldpTMgmtOid(true, "0.5.1", "2", 16,
				[]int{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			wantKey: "0.5.1",
			wantIP:  "2001:db8:0:0:0:0:0:1",
		},
		{
			name: "ipv6 address length mismatch",
			oid: lldpTMgmtOid(true, "0.5.1", "2", 4,
				[]int{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			wantKey: "0.5.1",
		},
		{
			name:    "unknown subtype",
			oid:     lldpTMgmtOid(true, "0.5.1", "3", 4, []int{10, 0, 0, 7}),
			wantKey: "0.5.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ip := parseMgmtAddr(tt.oid)
			if key != tt.wantKey || ip != tt.wantIP {
				t.Fatalf("parseMgmtAddr(%q) = (%q, %q), want (%q, %q)",
					tt.oid, key, ip, tt.wantKey, tt.wantIP)
			}
		})
	}
}

// TestLldpTParseMgmtAddrIPv6NonNumeric covers the strconv.Atoi failure arm,
// which needs a hand-built OID with a non-numeric octet.
func TestLldpTParseMgmtAddrIPv6NonNumeric(t *testing.T) {
	octets := make([]string, 16)
	for i := range octets {
		octets[i] = "0"
	}
	for _, bad := range []int{0, 1, 15} {
		t.Run(fmt.Sprintf("octet%d", bad), func(t *testing.T) {
			o := slices.Clone(octets)
			o[bad] = "xx"
			oid := "." + oidRemManAddr + ".0.5.1.2.16." + strings.Join(o, ".")
			key, ip := parseMgmtAddr(oid)
			if key != "0.5.1" || ip != "" {
				t.Fatalf("parseMgmtAddr(%q) = (%q, %q), want (%q, %q)", oid, key, ip, "0.5.1", "")
			}
		})
	}
}

func TestLldpTDiscoverNeighborsLocalSystemName(t *testing.T) {
	t.Run("get succeeds", func(t *testing.T) {
		m := &mockSnmpQuerier{getFunc: lldpTSysNameOK("switch-a")}
		result := discoverLldpNeighbors(m, "dev-1", "job-1", false)
		if result.LocalSystemName != "switch-a" {
			t.Fatalf("LocalSystemName = %q, want %q", result.LocalSystemName, "switch-a")
		}
		if result.DeviceId != "dev-1" || result.JobId != "job-1" {
			t.Fatalf("ids = (%q, %q), want (dev-1, job-1)", result.DeviceId, result.JobId)
		}
		if len(result.Neighbors) != 0 {
			t.Fatalf("Neighbors = %v, want empty", result.Neighbors)
		}
	})

	t.Run("get errors", func(t *testing.T) {
		m := &mockSnmpQuerier{getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
			return nil, errors.New("snmp timeout")
		}}
		result := discoverLldpNeighbors(m, "dev-2", "job-2", false)
		if result.LocalSystemName != "" {
			t.Fatalf("LocalSystemName = %q, want empty", result.LocalSystemName)
		}
	})

	t.Run("get returns no variables", func(t *testing.T) {
		m := &mockSnmpQuerier{getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
			return lldpTPacket(), nil
		}}
		result := discoverLldpNeighbors(m, "dev-3", "job-3", false)
		if result.LocalSystemName != "" {
			t.Fatalf("LocalSystemName = %q, want empty", result.LocalSystemName)
		}
	})

	t.Run("sentinel system name stays empty", func(t *testing.T) {
		m := &mockSnmpQuerier{getFunc: func([]string) (*gosnmp.SnmpPacket, error) {
			return lldpTPacket(gosnmp.SnmpPDU{
				Name:  oidLocSysName,
				Type:  gosnmp.EndOfMibView,
				Value: nil,
			}), nil
		}}
		result := discoverLldpNeighbors(m, "dev-4", "job-4", false)
		if result.LocalSystemName != "" {
			t.Fatalf("LocalSystemName = %q, want empty", result.LocalSystemName)
		}
	})
}

func TestLldpTDiscoverNeighborsWalkErrors(t *testing.T) {
	fullTable := map[string][]gosnmp.SnmpPDU{
		oidLocPortDesc:  {lldpTPdu("."+oidLocPortDesc+".5", "ether5")},
		oidRemChassisId: {lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a")},
		oidRemSysName:   {lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a")},
		oidRemPortDesc:  {lldpTPdu("."+oidRemPortDesc+".0.5.1", "eth0")},
		oidRemPortId:    {lldpTPdu("."+oidRemPortId+".0.5.1", "aa:bb:cc")},
		oidRemManAddr: {lldpTPdu(
			lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 1, 2, 3}), "")},
	}

	t.Run("local port walk error continues", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc:      lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(fullTable),
			walkErrs:     map[string]error{oidLocPortDesc: errors.New("locport boom")},
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d, want 1", len(result.Neighbors))
		}
		// No local port descriptions -> synthetic fallback name.
		if got := result.Neighbors[0].LocalPort; got != "port-5" {
			t.Fatalf("LocalPort = %q, want %q", got, "port-5")
		}
		if got := result.Neighbors[0].RemotePort; got != "eth0" {
			t.Fatalf("RemotePort = %q, want %q", got, "eth0")
		}
	})

	t.Run("remote sys name walk error continues with chassis ID", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc:      lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(fullTable),
			walkErrs:     map[string]error{oidRemSysName: errors.New("remsys boom")},
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %v, want one", result.Neighbors)
		}
		if result.Neighbors[0].NeighborName != "chassis-a" {
			t.Fatalf("NeighborName = %q, want chassis-a", result.Neighbors[0].NeighborName)
		}
		if result.LocalSystemName != "switch-a" {
			t.Fatalf("LocalSystemName = %q, want %q", result.LocalSystemName, "switch-a")
		}
	})

	t.Run("no chassis rows returns no neighbors", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc: lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
				oidLocPortDesc: {lldpTPdu("."+oidLocPortDesc+".5", "ether5")},
			}),
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 0 {
			t.Fatalf("Neighbors = %v, want empty", result.Neighbors)
		}
	})

	t.Run("remote port desc walk error continues", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc:      lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(fullTable),
			walkErrs:     map[string]error{oidRemPortDesc: errors.New("remportdesc boom")},
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d, want 1", len(result.Neighbors))
		}
		n := result.Neighbors[0]
		if n.RemotePort != "" {
			t.Fatalf("RemotePort = %q, want empty", n.RemotePort)
		}
		if n.RemotePortId != "aa:bb:cc" || n.LocalPort != "ether5" {
			t.Fatalf("neighbor = %+v, want RemotePortId aa:bb:cc / LocalPort ether5", n)
		}
	})

	t.Run("remote port id walk error continues", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc:      lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(fullTable),
			walkErrs:     map[string]error{oidRemPortId: errors.New("remportid boom")},
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d, want 1", len(result.Neighbors))
		}
		if got := result.Neighbors[0].RemotePortId; got != "" {
			t.Fatalf("RemotePortId = %q, want empty", got)
		}
		if got := result.Neighbors[0].ManagementAddresses; !slices.Equal(got, []string{"10.1.2.3"}) {
			t.Fatalf("ManagementAddresses = %v, want [10.1.2.3]", got)
		}
	})

	t.Run("mgmt addr walk error continues", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc:      lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(fullTable),
			walkErrs:     map[string]error{oidRemManAddr: errors.New("manaddr boom")},
		}
		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d, want 1", len(result.Neighbors))
		}
		if got := result.Neighbors[0].ManagementAddresses; len(got) != 0 {
			t.Fatalf("ManagementAddresses = %v, want empty", got)
		}
	})
}

func TestLldpTDiscoverNeighborsAssembly(t *testing.T) {
	m := &mockSnmpQuerier{
		getFunc: lldpTSysNameOK("core-sw"),
		walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
			oidLocPortDesc: {
				lldpTPdu("."+oidLocPortDesc+".5", "ether5"),
				// Suffix-less OID -> extractSuffix "" -> skipped.
				lldpTPdu(oidLocPortDesc, "ignored"),
			},
			oidRemChassisId: {
				lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a"),
				lldpTPdu(oidRemChassisId+".0.9.1", "chassis-b"),
				lldpTPdu("."+oidRemChassisId+".0.7.1", ""),
				lldpTPdu(oidRemChassisId, "ignored"),
			},
			oidRemSysName: {
				lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a"),
				// No local port description for port 9 -> "port-9" fallback.
				lldpTPdu(oidRemSysName+".0.9.1", "peer-b"),
				// A row with no system name, chassis ID, or management address has
				// no useful identity and is skipped.
				lldpTPdu("."+oidRemSysName+".0.7.1", ""),
				// Unparsable key -> not recorded at all.
				lldpTPdu(".1.2.3.4", "bogus"),
			},
			oidRemPortDesc: {
				lldpTPdu("."+oidRemPortDesc+".0.5.1", "eth0"),
				lldpTPdu(oidRemPortDesc, "ignored"),
			},
			oidRemPortId: {
				lldpTPdu("."+oidRemPortId+".0.5.1", "aa:bb:cc:dd:ee:ff"),
				lldpTPdu(oidRemPortId, "ignored"),
			},
			oidRemManAddr: {
				lldpTPdu(lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 1, 2, 3}), ""),
				lldpTPdu(lldpTMgmtOid(false, "0.5.1", "1", 4, []int{10, 1, 2, 4}), ""),
				// Unknown subtype -> ip empty -> skipped.
				lldpTPdu(lldpTMgmtOid(true, "0.5.1", "9", 4, []int{10, 1, 2, 5}), ""),
				// Non-matching OID -> key empty -> skipped.
				lldpTPdu(".1.2.3.4.5.6.7.8.9", ""),
			},
		}),
	}

	result := discoverLldpNeighbors(m, "dev-9", "job-9", false)

	if result.LocalSystemName != "core-sw" {
		t.Fatalf("LocalSystemName = %q, want core-sw", result.LocalSystemName)
	}
	if len(result.Neighbors) != 2 {
		t.Fatalf("Neighbors = %d (%+v), want 2", len(result.Neighbors), result.Neighbors)
	}

	// sortedLldpKeys gives deterministic order: "0.5.1" before "0.9.1".
	first := result.Neighbors[0]
	if first.NeighborName != "peer-a" {
		t.Fatalf("Neighbors[0].NeighborName = %q, want peer-a", first.NeighborName)
	}
	if first.LocalPort != "ether5" {
		t.Fatalf("Neighbors[0].LocalPort = %q, want ether5", first.LocalPort)
	}
	if first.RemotePort != "eth0" {
		t.Fatalf("Neighbors[0].RemotePort = %q, want eth0", first.RemotePort)
	}
	if first.RemotePortId != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("Neighbors[0].RemotePortId = %q, want aa:bb:cc:dd:ee:ff", first.RemotePortId)
	}
	if first.RemoteChassisId != "chassis-a" {
		t.Fatalf("Neighbors[0].RemoteChassisId = %q, want chassis-a", first.RemoteChassisId)
	}
	if !slices.Equal(first.ManagementAddresses, []string{"10.1.2.3", "10.1.2.4"}) {
		t.Fatalf("Neighbors[0].ManagementAddresses = %v, want [10.1.2.3 10.1.2.4]",
			first.ManagementAddresses)
	}

	second := result.Neighbors[1]
	if second.NeighborName != "peer-b" {
		t.Fatalf("Neighbors[1].NeighborName = %q, want peer-b", second.NeighborName)
	}
	if second.LocalPort != "port-9" {
		t.Fatalf("Neighbors[1].LocalPort = %q, want port-9", second.LocalPort)
	}
	if second.RemoteChassisId != "chassis-b" {
		t.Fatalf("Neighbors[1].RemoteChassisId = %q, want chassis-b", second.RemoteChassisId)
	}
	if second.RemotePort != "" || second.RemotePortId != "" {
		t.Fatalf("Neighbors[1] remote fields = (%q, %q), want empty",
			second.RemotePort, second.RemotePortId)
	}
	if len(second.ManagementAddresses) != 0 {
		t.Fatalf("Neighbors[1].ManagementAddresses = %v, want empty", second.ManagementAddresses)
	}
}

func TestLldpTDiscoverNeighborsWithoutSystemNames(t *testing.T) {
	tests := []struct {
		name        string
		systemNames []gosnmp.SnmpPDU
		wantNames   []string
	}{
		{
			name: "one row has no system name",
			systemNames: []gosnmp.SnmpPDU{
				lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a"),
			},
			wantNames: []string{"peer-a", "chassis-b"},
		},
		{
			name:      "no rows have system names",
			wantNames: []string{"chassis-a", "chassis-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockSnmpQuerier{
				getFunc: lldpTSysNameOK("switch-a"),
				walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
					oidLocPortDesc: {
						lldpTPdu("."+oidLocPortDesc+".5", "ether5"),
						lldpTPdu("."+oidLocPortDesc+".9", "ether9"),
					},
					oidRemChassisId: {
						lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a"),
						lldpTPdu("."+oidRemChassisId+".0.9.1", "chassis-b"),
					},
					oidRemSysName: tt.systemNames,
					oidRemPortDesc: {
						lldpTPdu("."+oidRemPortDesc+".0.9.1", "wifi0"),
					},
					oidRemManAddr: {
						lldpTPdu(lldpTMgmtOid(true, "0.9.1", "1", 4, []int{10, 1, 2, 9}), ""),
					},
				}),
			}

			result := discoverLldpNeighbors(m, "dev", "job", false)
			if len(result.Neighbors) != 2 {
				t.Fatalf("Neighbors = %d (%+v), want 2", len(result.Neighbors), result.Neighbors)
			}
			gotNames := []string{result.Neighbors[0].NeighborName, result.Neighbors[1].NeighborName}
			if !slices.Equal(gotNames, tt.wantNames) {
				t.Fatalf("neighbor names = %v, want %v", gotNames, tt.wantNames)
			}

			unnamed := result.Neighbors[1]
			if unnamed.RemoteChassisId != "chassis-b" {
				t.Fatalf("RemoteChassisId = %q, want chassis-b", unnamed.RemoteChassisId)
			}
			if unnamed.LocalPort != "ether9" {
				t.Fatalf("LocalPort = %q, want ether9", unnamed.LocalPort)
			}
			if unnamed.RemotePort != "wifi0" {
				t.Fatalf("RemotePort = %q, want wifi0", unnamed.RemotePort)
			}
			if !slices.Equal(unnamed.ManagementAddresses, []string{"10.1.2.9"}) {
				t.Fatalf("ManagementAddresses = %v, want [10.1.2.9]", unnamed.ManagementAddresses)
			}
		})
	}

	t.Run("management address is final identity fallback", func(t *testing.T) {
		m := &mockSnmpQuerier{
			getFunc: lldpTSysNameOK("switch-a"),
			walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
				oidRemChassisId: {
					lldpTPdu("."+oidRemChassisId+".0.5.1", ""),
					lldpTPdu("."+oidRemChassisId+".0.9.1", ""),
				},
				oidRemManAddr: {
					lldpTPdu(lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 1, 2, 5}), ""),
				},
			}),
		}

		result := discoverLldpNeighbors(m, "dev", "job", false)
		if len(result.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d (%+v), want 1", len(result.Neighbors), result.Neighbors)
		}
		if result.Neighbors[0].NeighborName != "10.1.2.5" {
			t.Fatalf("NeighborName = %q, want 10.1.2.5", result.Neighbors[0].NeighborName)
		}
	})
}

func TestLldpTDiscoverNeighborsEmptyIndexParts(t *testing.T) {
	m := &mockSnmpQuerier{
		getFunc: lldpTSysNameOK("sw"),
		walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
			oidRemChassisId: {
				lldpTPdu("."+oidRemChassisId+"...", "chassis-weird"),
				lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a"),
			},
			oidRemSysName: {
				lldpTPdu("."+oidRemSysName+"...", "weird"),
				lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a"),
			},
		}),
	}
	result := discoverLldpNeighbors(m, "dev", "job", false)
	// "..." -> suffix ".." -> parts ["", "", ""] -> key ".." -> name "weird",
	// split on "." gives 3 empty parts so portNum is "" -> LocalPort "port-".
	names := make([]string, 0, len(result.Neighbors))
	for _, n := range result.Neighbors {
		names = append(names, n.NeighborName+"/"+n.LocalPort)
	}
	if !slices.Equal(names, []string{"weird/port-", "peer-a/port-5"}) {
		t.Fatalf("neighbors = %v, want [weird/port- peer-a/port-5]", names)
	}
}

func TestLldpTExecuteLldpTopologyJob(t *testing.T) {
	t.Run("nil snmp device", func(t *testing.T) {
		out := make(resultQueue, 1)
		executeLldpTopologyJob(context.Background(),
			&pb.AgentJob{DeviceId: "dev-1", JobId: "job-1"}, out)
		o := <-out
		if o.event != "lldp_topology_result" {
			t.Fatalf("event = %q, want lldp_topology_result", o.event)
		}
		got, ok := o.msg.(*pb.LldpTopologyResult)
		if !ok {
			t.Fatalf("message type = %T, want *pb.LldpTopologyResult", o.msg)
		}
		if got.DeviceId != "dev-1" || got.JobId != "job-1" {
			t.Fatalf("result ids = (%q, %q), want (dev-1, job-1)", got.DeviceId, got.JobId)
		}
		if len(got.Neighbors) != 0 || got.LocalSystemName != "" {
			t.Fatalf("result = %+v, want empty neighbors and system name", got)
		}
		if got.Timestamp == 0 {
			t.Fatal("Timestamp = 0, want non-zero")
		}
	})

	t.Run("dial error", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()
		snmpDial = func(context.Context, *pb.SnmpDevice) (snmpQuerier, func(), error) {
			return nil, nil, errors.New("dial refused")
		}

		out := make(resultQueue, 1)
		executeLldpTopologyJob(context.Background(), &pb.AgentJob{
			DeviceId:   "dev-2",
			JobId:      "job-2",
			SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1"},
		}, out)
		o := <-out
		if o.event != "lldp_topology_result" {
			t.Fatalf("event = %q, want lldp_topology_result", o.event)
		}
		got, ok := o.msg.(*pb.LldpTopologyResult)
		if !ok {
			t.Fatalf("message type = %T, want *pb.LldpTopologyResult", o.msg)
		}
		if got.DeviceId != "dev-2" || got.JobId != "job-2" {
			t.Fatalf("result ids = (%q, %q), want (dev-2, job-2)", got.DeviceId, got.JobId)
		}
		if len(got.Neighbors) != 0 {
			t.Fatalf("Neighbors = %v, want empty", got.Neighbors)
		}
	})

	t.Run("success", func(t *testing.T) {
		orig := snmpDial
		defer func() { snmpDial = orig }()

		closed := false
		m := &mockSnmpQuerier{
			getFunc: lldpTSysNameOK("core-sw"),
			walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
				oidLocPortDesc:  {lldpTPdu("."+oidLocPortDesc+".5", "ether5")},
				oidRemChassisId: {lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a")},
				oidRemSysName:   {lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a")},
				oidRemPortDesc:  {lldpTPdu("."+oidRemPortDesc+".0.5.1", "eth0")},
				oidRemPortId:    {lldpTPdu("."+oidRemPortId+".0.5.1", "aa:bb")},
				oidRemManAddr: {lldpTPdu(
					lldpTMgmtOid(true, "0.5.1", "1", 4, []int{10, 1, 2, 3}), "")},
			}),
		}
		var gotCtx context.Context
		var gotDev *pb.SnmpDevice
		snmpDial = func(ctx context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
			gotCtx = ctx
			gotDev = dev
			return m, func() { closed = true }, nil
		}

		out := make(resultQueue, 1)
		dev := &pb.SnmpDevice{Ip: "10.0.0.1", Version: "2c"}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		executeLldpTopologyJob(ctx, &pb.AgentJob{
			DeviceId:   "dev-3",
			JobId:      "job-3",
			SnmpDevice: dev,
		}, out)

		if gotDev != dev {
			t.Fatalf("snmpDial got device %+v, want %+v", gotDev, dev)
		}
		if gotCtx != ctx {
			t.Fatal("snmpDial did not receive the job context")
		}
		if !closed {
			t.Fatal("close function was not called")
		}

		o := <-out
		if o.event != "lldp_topology_result" {
			t.Fatalf("event = %q, want lldp_topology_result", o.event)
		}
		got, ok := o.msg.(*pb.LldpTopologyResult)
		if !ok {
			t.Fatalf("message type = %T, want *pb.LldpTopologyResult", o.msg)
		}
		if got.DeviceId != "dev-3" || got.JobId != "job-3" {
			t.Fatalf("result ids = (%q, %q), want (dev-3, job-3)", got.DeviceId, got.JobId)
		}
		if got.LocalSystemName != "core-sw" {
			t.Fatalf("LocalSystemName = %q, want core-sw", got.LocalSystemName)
		}
		if len(got.Neighbors) != 1 {
			t.Fatalf("Neighbors = %d, want 1", len(got.Neighbors))
		}
		n := got.Neighbors[0]
		if n.NeighborName != "peer-a" || n.LocalPort != "ether5" ||
			n.RemotePort != "eth0" || n.RemotePortId != "aa:bb" ||
			n.RemoteChassisId != "chassis-a" {
			t.Fatalf("neighbor = %+v, want peer-a/ether5/eth0/aa:bb/chassis-a", n)
		}
		if !slices.Equal(n.ManagementAddresses, []string{"10.1.2.3"}) {
			t.Fatalf("ManagementAddresses = %v, want [10.1.2.3]", n.ManagementAddresses)
		}
	})
}

func TestLldpTExecuteLldpTopologyJobWalkStrategy(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		wantBulk bool
	}{
		{name: "v1 uses Walk", version: "v1"},
		{name: "v2c uses BulkWalk", version: "2c", wantBulk: true},
	}
	wantRoots := []string{
		oidLocPortDesc,
		oidRemChassisId,
		oidRemSysName,
		oidRemPortDesc,
		oidRemPortId,
		oidRemManAddr,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := snmpDial
			defer func() { snmpDial = orig }()

			m := &mockSnmpQuerier{
				getFunc: lldpTSysNameOK("core-sw"),
				walkStepFunc: lldpTWalk(map[string][]gosnmp.SnmpPDU{
					oidRemSysName:   {lldpTPdu("."+oidRemSysName+".0.5.1", "peer-a")},
					oidRemChassisId: {lldpTPdu("."+oidRemChassisId+".0.5.1", "chassis-a")},
				}),
			}
			snmpDial = func(context.Context, *pb.SnmpDevice) (snmpQuerier, func(), error) {
				return m, func() {}, nil
			}

			out := make(resultQueue, 1)
			executeLldpTopologyJob(context.Background(), &pb.AgentJob{
				DeviceId:   "dev-walk",
				JobId:      "job-walk",
				SnmpDevice: &pb.SnmpDevice{Ip: "10.0.0.1", Version: tt.version},
			}, out)
			<-out

			if tt.wantBulk {
				if !slices.Equal(m.bulkWalkRoots, wantRoots) {
					t.Fatalf("BulkWalk roots = %v, want %v", m.bulkWalkRoots, wantRoots)
				}
				if len(m.walkRoots) != 0 {
					t.Fatalf("Walk roots = %v, want none", m.walkRoots)
				}
			} else {
				if !slices.Equal(m.walkRoots, wantRoots) {
					t.Fatalf("Walk roots = %v, want %v", m.walkRoots, wantRoots)
				}
				if len(m.bulkWalkRoots) != 0 {
					t.Fatalf("BulkWalk roots = %v, want none", m.bulkWalkRoots)
				}
			}
		})
	}
}

// ---- Property tests ----

// lldpTNumericOID draws a dotted numeric OID with the given number of parts.
func lldpTNumericOID(t *rapid.T, label string, minParts, maxParts int) string {
	n := rapid.IntRange(minParts, maxParts).Draw(t, label+"_len")
	parts := make([]string, n)
	for i := range parts {
		parts[i] = strconv.Itoa(rapid.IntRange(0, 4095).Draw(t, fmt.Sprintf("%s_%d", label, i)))
	}
	return strings.Join(parts, ".")
}

func TestPropLldpExtractSuffix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := lldpTNumericOID(t, "base", 1, 8)
		suffix := lldpTNumericOID(t, "suffix", 1, 6)

		if got := extractSuffix("."+base+"."+suffix, base); got != suffix {
			t.Fatalf("extractSuffix(%q, %q) = %q, want %q", "."+base+"."+suffix, base, got, suffix)
		}
		if got := extractSuffix(base+"."+suffix, base); got != suffix {
			t.Fatalf("extractSuffix(%q, %q) = %q, want %q", base+"."+suffix, base, got, suffix)
		}

		// An OID that does not carry base as a prefix yields "".
		other := lldpTNumericOID(t, "other", 1, 8)
		for _, oid := range []string{other, "." + other} {
			if strings.HasPrefix(oid, "."+base+".") || strings.HasPrefix(oid, base+".") {
				continue
			}
			if got := extractSuffix(oid, base); got != "" {
				t.Fatalf("extractSuffix(%q, %q) = %q, want empty", oid, base, got)
			}
		}
	})
}

func TestPropLldpParseRemoteKey(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := lldpTNumericOID(t, "base", 1, 8)
		nParts := rapid.IntRange(1, 6).Draw(t, "nParts")
		parts := make([]string, nParts)
		for i := range parts {
			parts[i] = strconv.Itoa(rapid.IntRange(0, 4095).Draw(t, fmt.Sprintf("p%d", i)))
		}
		oid := "." + base + "." + strings.Join(parts, ".")

		want := ""
		if nParts >= 3 {
			want = parts[0] + "." + parts[1] + "." + parts[2]
		}
		if got := parseRemoteKey(oid, base); got != want {
			t.Fatalf("parseRemoteKey(%q, %q) = %q, want %q", oid, base, got, want)
		}
	})
}

func TestPropLldpParseMgmtAddrIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := make([]int, 4)
		for i := range octets {
			octets[i] = rapid.IntRange(0, 255).Draw(t, fmt.Sprintf("octet%d", i))
		}
		key := fmt.Sprintf("%d.%d.%d",
			rapid.IntRange(0, 999).Draw(t, "timeMark"),
			rapid.IntRange(1, 999).Draw(t, "portNum"),
			rapid.IntRange(1, 999).Draw(t, "remIndex"))
		oid := lldpTMgmtOid(rapid.Bool().Draw(t, "leadingDot"), key, "1", 4, octets)

		gotKey, ip := parseMgmtAddr(oid)
		if gotKey != key {
			t.Fatalf("parseMgmtAddr(%q) key = %q, want %q", oid, gotKey, key)
		}
		v4 := net.ParseIP(ip).To4()
		if v4 == nil {
			t.Fatalf("parseMgmtAddr(%q) ip = %q, not a valid IPv4", oid, ip)
		}
		for i, o := range octets {
			if int(v4[i]) != o {
				t.Fatalf("ip %q octet %d = %d, want %d", ip, i, v4[i], o)
			}
		}
	})
}

func TestPropLldpParseMgmtAddrIPv6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := make([]int, 16)
		for i := range octets {
			octets[i] = rapid.IntRange(0, 255).Draw(t, fmt.Sprintf("octet%d", i))
		}
		key := fmt.Sprintf("%d.%d.%d",
			rapid.IntRange(0, 999).Draw(t, "timeMark"),
			rapid.IntRange(1, 999).Draw(t, "portNum"),
			rapid.IntRange(1, 999).Draw(t, "remIndex"))
		oid := lldpTMgmtOid(rapid.Bool().Draw(t, "leadingDot"), key, "2", 16, octets)

		gotKey, ip := parseMgmtAddr(oid)
		if gotKey != key {
			t.Fatalf("parseMgmtAddr(%q) key = %q, want %q", oid, gotKey, key)
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("parseMgmtAddr(%q) ip = %q, not a valid IP", oid, ip)
		}
		v16 := parsed.To16()
		if v16 == nil {
			t.Fatalf("ip %q has no 16-byte form", ip)
		}
		for i, o := range octets {
			if int(v16[i]) != o {
				t.Fatalf("ip %q octet %d = %d, want %d", ip, i, v16[i], o)
			}
		}
	})
}

func TestPropLldpSortedKeys(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := rapid.MapOf(rapid.String(), rapid.String()).Draw(t, "values")

		got := sortedLldpKeys(m)
		if len(got) != len(m) {
			t.Fatalf("sortedLldpKeys len = %d, want %d", len(got), len(m))
		}
		if !slices.IsSorted(got) {
			t.Fatalf("sortedLldpKeys = %v, not sorted", got)
		}
		want := make([]string, 0, len(m))
		for k := range m {
			want = append(want, k)
		}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("sortedLldpKeys = %v, want permutation %v", got, want)
		}
	})
}
