package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// LLDP-MIB OIDs (IEEE 802.1AB)
const (
	oidLocSysName  = "1.0.8802.1.1.2.1.3.3.0"
	oidLocPortDesc = "1.0.8802.1.1.2.1.3.7.1.4"
	oidRemPortId   = "1.0.8802.1.1.2.1.4.1.1.7"
	oidRemPortDesc = "1.0.8802.1.1.2.1.4.1.1.8"
	oidRemSysName  = "1.0.8802.1.1.2.1.4.1.1.9"
	oidRemManAddr  = "1.0.8802.1.1.2.1.4.2.1.3"
)

// executeLldpTopologyJob performs LLDP neighbor discovery via SNMP.
func executeLldpTopologyJob(ctx context.Context, job *pb.AgentJob, resultCh chan<- *pb.LldpTopologyResult) {
	deviceID := job.DeviceId
	jobID := job.JobId

	if job.SnmpDevice == nil {
		slog.Error("missing SNMP config for LLDP job", "job_id", jobID, "device_id", deviceID)
		return
	}

	snmpDev := job.SnmpDevice
	client, err := newSnmpConn(snmpDev)
	if err != nil {
		slog.Error("failed to connect SNMP for LLDP", "job_id", jobID, "device_id", deviceID, "error", err)
		return
	}
	defer func() {
		if err := client.Conn.Close(); err != nil {
			slog.Debug("SNMP close error", "error", err)
		}
	}()

	result, err := discoverLldpNeighbors(client, deviceID, jobID)
	if err != nil {
		slog.Error("LLDP discovery failed", "job_id", jobID, "device_id", deviceID, "error", err)
		return
	}

	select {
	case resultCh <- result:
		slog.Info("LLDP topology discovered", "job_id", jobID, "device_id", deviceID, "neighbors", len(result.Neighbors))
	case <-ctx.Done():
		slog.Warn("LLDP result send cancelled", "job_id", jobID)
	}
}

// discoverLldpNeighbors walks LLDP-MIB tables and returns discovered neighbors.
func discoverLldpNeighbors(client *gosnmp.GoSNMP, deviceID, jobID string) (*pb.LldpTopologyResult, error) {
	now := time.Now().Unix()
	result := &pb.LldpTopologyResult{
		DeviceId:  deviceID,
		JobId:     jobID,
		Timestamp: now,
	}

	// Get local system name
	sysNamePkt, err := client.Get([]string{oidLocSysName})
	if err == nil && len(sysNamePkt.Variables) > 0 {
		result.LocalSystemName = snmpValueToString(sysNamePkt.Variables[0])
	}

	// Walk local port descriptions (indexed by port number)
	localPorts := make(map[string]string)
	if err := client.Walk(oidLocPortDesc, func(pdu gosnmp.SnmpPDU) error {
		portNum := extractSuffix(pdu.Name, oidLocPortDesc)
		if portNum != "" {
			localPorts[portNum] = snmpValueToString(pdu)
		}
		return nil
	}); err != nil {
		slog.Warn("failed to walk local ports", "error", err)
	}

	// Walk remote system names (indexed by timeMark.portNum.remIndex)
	sysNames := make(map[string]string)
	if err := client.Walk(oidRemSysName, func(pdu gosnmp.SnmpPDU) error {
		key := parseRemoteKey(pdu.Name, oidRemSysName)
		if key != "" {
			sysNames[key] = snmpValueToString(pdu)
		}
		return nil
	}); err != nil {
		slog.Warn("failed to walk remote sys names", "error", err)
		return result, nil // Return empty result, not an error
	}

	// If no neighbors found, return early
	if len(sysNames) == 0 {
		return result, nil
	}

	// Walk remote port descriptions
	remotePorts := make(map[string]string)
	_ = client.Walk(oidRemPortDesc, func(pdu gosnmp.SnmpPDU) error {
		key := parseRemoteKey(pdu.Name, oidRemPortDesc)
		if key != "" {
			remotePorts[key] = snmpValueToString(pdu)
		}
		return nil
	})

	// Walk remote port IDs (fallback when description is empty)
	remotePortIds := make(map[string]string)
	_ = client.Walk(oidRemPortId, func(pdu gosnmp.SnmpPDU) error {
		key := parseRemoteKey(pdu.Name, oidRemPortId)
		if key != "" {
			remotePortIds[key] = snmpValueToString(pdu)
		}
		return nil
	})

	// Walk management addresses (indexed by timeMark.portNum.remIndex.addrSubtype.addrLen.addr[bytes])
	mgmtAddrs := make(map[string][]string)
	_ = client.Walk(oidRemManAddr, func(pdu gosnmp.SnmpPDU) error {
		key, ip := parseMgmtAddr(pdu.Name)
		if key != "" && ip != "" {
			mgmtAddrs[key] = append(mgmtAddrs[key], ip)
		}
		return nil
	})

	// Assemble neighbor list
	for key, neighborName := range sysNames {
		if neighborName == "" {
			continue
		}

		parts := strings.Split(key, ".")
		if len(parts) < 2 {
			continue
		}
		portNum := parts[1] // timeMark.portNum.remIndex -> parts[1] is portNum

		localPort := localPorts[portNum]
		if localPort == "" {
			localPort = "port-" + portNum
		}

		neighbor := &pb.LldpNeighbor{
			NeighborName:        neighborName,
			LocalPort:           localPort,
			RemotePort:          remotePorts[key],
			RemotePortId:        remotePortIds[key],
			ManagementAddresses: mgmtAddrs[key],
		}

		result.Neighbors = append(result.Neighbors, neighbor)
	}

	return result, nil
}

// extractSuffix strips the base OID prefix and returns the suffix.
func extractSuffix(oid, base string) string {
	prefix := "." + base + "."
	if strings.HasPrefix(oid, prefix) {
		return strings.TrimPrefix(oid, prefix)
	}
	// Try without leading dot on oid
	prefix = base + "."
	if strings.HasPrefix(oid, prefix) {
		return strings.TrimPrefix(oid, prefix)
	}
	return ""
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
	// parts[4] is addrLen (we trust the subtype to determine length)

	switch addrSubtype {
	case "1": // IPv4
		if len(parts) < 9 {
			return key, ""
		}
		ip = strings.Join(parts[5:9], ".")
	case "2": // IPv6
		if len(parts) < 21 {
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
