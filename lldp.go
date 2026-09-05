// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// LLDP-MIB OIDs (IEEE 802.1AB)
const (
	oidLocSysName   = "1.0.8802.1.1.2.1.3.3.0"
	oidLocPortDesc  = "1.0.8802.1.1.2.1.3.7.1.4"
	oidRemChassisId = "1.0.8802.1.1.2.1.4.1.1.5"
	oidRemPortId    = "1.0.8802.1.1.2.1.4.1.1.7"
	oidRemPortDesc  = "1.0.8802.1.1.2.1.4.1.1.8"
	oidRemSysName   = "1.0.8802.1.1.2.1.4.1.1.9"
	oidRemManAddr   = "1.0.8802.1.1.2.1.4.2.1.3"
)

// executeLldpTopologyJob performs LLDP neighbor discovery via SNMP.
func executeLldpTopologyJob(ctx context.Context, job *pb.AgentJob, out resultQueue) {
	deviceID := job.DeviceId
	jobID := job.JobId
	timestamp := time.Now().Unix()

	if job.SnmpDevice == nil {
		slog.Error("missing SNMP config for LLDP job", "job_id", jobID, "device_id", deviceID)
		sendResult(ctx, out, "lldp_topology_result", &pb.LldpTopologyResult{
			DeviceId:  deviceID,
			JobId:     jobID,
			Timestamp: timestamp,
		}, jobID)
		return
	}

	snmpDev := job.SnmpDevice
	client, closeConn, err := snmpDial(ctx, snmpDev)
	if err != nil {
		slog.Error("failed to connect SNMP for LLDP", "job_id", jobID, "device_id", deviceID, "error", err)
		sendResult(ctx, out, "lldp_topology_result", &pb.LldpTopologyResult{
			DeviceId:  deviceID,
			JobId:     jobID,
			Timestamp: timestamp,
		}, jobID)
		return
	}
	defer closeConn()

	result := discoverLldpNeighbors(client, deviceID, jobID, !isSnmpV1(snmpDev.Version))

	sendResult(ctx, out, "lldp_topology_result", result, jobID)
	slog.Info("LLDP topology discovered", "job_id", jobID, "device_id", deviceID, "neighbors", len(result.Neighbors))
}

// discoverLldpNeighbors walks LLDP-MIB tables and returns discovered neighbors.
// Table walk failures are logged and tolerated, so discovery never fails outright.
func discoverLldpNeighbors(client snmpQuerier, deviceID, jobID string, useBulk bool) *pb.LldpTopologyResult {
	now := time.Now().Unix()
	result := &pb.LldpTopologyResult{
		DeviceId:  deviceID,
		JobId:     jobID,
		Timestamp: now,
	}

	walk := client.Walk
	if useBulk {
		walk = client.BulkWalk
	}

	// Get local system name
	sysNamePkt, err := client.Get([]string{oidLocSysName})
	if err == nil && len(sysNamePkt.Variables) > 0 && snmpValueUsable(sysNamePkt.Variables[0]) {
		result.LocalSystemName = snmpValueToString(sysNamePkt.Variables[0])
	}

	localPorts, err := walkTable(walk, oidLocPortDesc, func(oid string) string {
		return extractSuffix(oid, oidLocPortDesc)
	})
	if err != nil {
		slog.Warn("failed to walk local ports", "error", err)
	}

	chassisIDs, err := walkTable(walk, oidRemChassisId, func(oid string) string {
		return parseRemoteKey(oid, oidRemChassisId)
	})
	if err != nil {
		slog.Warn("failed to walk remote chassis IDs", "error", err)
	}

	sysNames, err := walkTable(walk, oidRemSysName, func(oid string) string {
		return parseRemoteKey(oid, oidRemSysName)
	})
	if err != nil {
		slog.Warn("failed to walk remote sys names", "error", err)
	}

	remotePorts, err := walkTable(walk, oidRemPortDesc, func(oid string) string {
		return parseRemoteKey(oid, oidRemPortDesc)
	})
	if err != nil {
		slog.Warn("failed to walk remote port descriptions", "error", err)
	}

	remotePortIDs, err := walkTable(walk, oidRemPortId, func(oid string) string {
		return parseRemoteKey(oid, oidRemPortId)
	})
	if err != nil {
		slog.Warn("failed to walk remote port IDs", "error", err)
	}

	// Management addresses have a variable-length index, so they cannot use walkTable.
	mgmtAddrs := make(map[string][]string)
	if err := walk(oidRemManAddr, func(pdu gosnmp.SnmpPDU) error {
		if !snmpValueUsable(pdu) {
			return nil
		}
		key, ip := parseMgmtAddr(pdu.Name)
		if key != "" && ip != "" {
			mgmtAddrs[key] = append(mgmtAddrs[key], ip)
		}
		return nil
	}); err != nil {
		slog.Warn("failed to walk management addresses", "error", err)
	}

	for _, key := range sortedLldpKeys(chassisIDs) {
		neighborName := sysNames[key]
		if neighborName == "" {
			neighborName = chassisIDs[key]
		}
		if neighborName == "" && len(mgmtAddrs[key]) > 0 {
			neighborName = mgmtAddrs[key][0]
		}
		if neighborName == "" {
			continue
		}

		// parseRemoteKey guarantees exactly timeMark.portNum.remIndex.
		parts := strings.Split(key, ".")
		portNum := parts[1]

		localPort := localPorts[portNum]
		if localPort == "" {
			localPort = "port-" + portNum
		}

		neighbor := &pb.LldpNeighbor{
			NeighborName:        neighborName,
			LocalPort:           localPort,
			RemotePort:          remotePorts[key],
			RemotePortId:        remotePortIDs[key],
			ManagementAddresses: mgmtAddrs[key],
			RemoteChassisId:     chassisIDs[key],
		}

		result.Neighbors = append(result.Neighbors, neighbor)
	}

	return result
}

// walkTable walks base and collects usable PDUs keyed by keyFn. It returns
// partial results with any walk error so callers can degrade discovery.
func walkTable(
	walk func(string, gosnmp.WalkFunc) error,
	base string,
	keyFn func(oid string) string,
) (map[string]string, error) {
	values := make(map[string]string)
	err := walk(base, func(pdu gosnmp.SnmpPDU) error {
		if !snmpValueUsable(pdu) {
			return nil
		}
		key := keyFn(pdu.Name)
		if key != "" {
			values[key] = snmpValueToString(pdu)
		}
		return nil
	})
	return values, err
}

func sortedLldpKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// extractSuffix strips the base OID prefix and returns the suffix.
func extractSuffix(oid, base string) string {
	oid = canonicalOID(oid)
	prefix := canonicalOID(base) + "."
	if !strings.HasPrefix(oid, prefix) {
		return ""
	}
	return strings.TrimPrefix(oid, prefix)
}

// parseRemoteKey extracts a remote table key from OID: timeMark.portNum.remIndex
func parseRemoteKey(oid, base string) string {
	suffix := extractSuffix(oid, base)
	if suffix == "" {
		return ""
	}
	parts := strings.SplitN(suffix, ".", 4)
	if len(parts) < 3 {
		return ""
	}
	// Return full key as string: timeMark.portNum.remIndex
	return parts[0] + "." + parts[1] + "." + parts[2]
}

// parseMgmtAddr parses a management address OID.
// Format: timeMark.portNum.remIndex.addrSubtype.addrLen.addr[bytes]
// addrSubtype 1 = IPv4 (4 bytes), 2 = IPv6 (16 bytes)
func parseMgmtAddr(oid string) (key string, ip string) {
	suffix := extractSuffix(oid, oidRemManAddr)
	if suffix == "" {
		return "", ""
	}

	parts := strings.Split(suffix, ".")
	// Minimum: timeMark(1) portNum(1) remIndex(1) addrSubtype(1) addrLen(1) addr(>=4)
	if len(parts) < 9 {
		return "", ""
	}

	// timeMark.portNum.remIndex
	key = parts[0] + "." + parts[1] + "." + parts[2]
	addrSubtype := parts[3]
	addrLen, err := strconv.Atoi(parts[4])
	if err != nil {
		return key, ""
	}

	// The index ends with exactly addrLen octets; anything longer is a row this
	// walk should not have produced.
	if len(parts) != 5+addrLen {
		return key, ""
	}

	switch addrSubtype {
	case "1": // IPv4
		if addrLen != net.IPv4len {
			return key, ""
		}
		ip = strings.Join(parts[5:9], ".")
	case "2": // IPv6
		if addrLen != net.IPv6len {
			return key, ""
		}
		// Convert 16 octets to IPv6 hex format
		var ipv6Parts []string
		for i := 0; i < 16; i += 2 {
			a, errA := strconv.Atoi(parts[5+i])
			b, errB := strconv.Atoi(parts[5+i+1])
			if errA != nil || errB != nil {
				return key, ""
			}
			ipv6Parts = append(ipv6Parts, fmt.Sprintf("%x", a*256+b))
		}
		ip = strings.Join(ipv6Parts, ":")
	default:
		return key, ""
	}

	// Validate IP address
	if net.ParseIP(ip) == nil {
		return key, ""
	}

	return key, ip
}
