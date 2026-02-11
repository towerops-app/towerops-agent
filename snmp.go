package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

// executeSnmpJob runs SNMP GET/WALK queries for a job and sends results.
func executeSnmpJob(job *pb.AgentJob, resultCh chan<- *pb.SnmpResult) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		return
	}

	conn, err := newSnmpConn(dev)
	if err != nil {
		slog.Error("snmp connect", "job_id", job.JobId, "device", dev.Ip, "error", err)
		return
	}
	defer conn.Conn.Close()

	oidValues := make(map[string]string)

	for _, q := range job.Queries {
		switch q.QueryType {
		case pb.QueryType_GET:
			for _, oid := range q.Oids {
				result, err := conn.Get([]string{oid})
				if err != nil {
					slog.Warn("snmp get failed", "device", dev.Ip, "oid", oid, "error", err)
					continue
				}
				for _, v := range result.Variables {
					if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.EndOfMibView {
						continue
					}
					oidValues[v.Name] = snmpValueToString(v)
				}
			}
		case pb.QueryType_WALK:
			for _, baseOID := range q.Oids {
				results, err := conn.BulkWalkAll(baseOID)
				if err != nil {
					slog.Warn("snmp walk failed", "device", dev.Ip, "oid", baseOID, "error", err)
					continue
				}
				for _, v := range results {
					if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.EndOfMibView {
						continue
					}
					oidValues[v.Name] = snmpValueToString(v)
				}
			}
		}
	}

	result := &pb.SnmpResult{
		DeviceId:  job.DeviceId,
		JobType:   job.JobType,
		JobId:     job.JobId,
		OidValues: oidValues,
		Timestamp: time.Now().Unix(),
	}

	slog.Info("snmp job complete", "job_id", job.JobId, "oids", len(oidValues))

	select {
	case resultCh <- result:
	default:
		slog.Warn("result channel full", "job_id", job.JobId)
	}
}

// executeCredentialTest tests SNMP credentials by reading sysDescr.0.
func executeCredentialTest(job *pb.AgentJob, resultCh chan<- *pb.CredentialTestResult) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		return
	}

	conn, err := newSnmpConn(dev)
	timestamp := time.Now().Unix()

	if err != nil {
		resultCh <- &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("connection failed: %v", err),
			Timestamp:    timestamp,
		}
		return
	}
	defer conn.Conn.Close()

	result, err := conn.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		resultCh <- &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("SNMP test failed: %v", err),
			Timestamp:    timestamp,
		}
		return
	}

	sysDescr := ""
	if len(result.Variables) > 0 {
		sysDescr = snmpValueToString(result.Variables[0])
	}

	resultCh <- &pb.CredentialTestResult{
		TestId:            job.JobId,
		Success:           true,
		SystemDescription: sysDescr,
		Timestamp:         timestamp,
	}
}

// newSnmpConn creates a gosnmp.GoSNMP connection from protobuf device config.
func newSnmpConn(dev *pb.SnmpDevice) (*gosnmp.GoSNMP, error) {
	conn := &gosnmp.GoSNMP{
		Target:  dev.Ip,
		Port:    uint16(dev.Port),
		Timeout: 10 * time.Second,
		Retries: 2,
	}

	// Transport
	if dev.Transport == "tcp" {
		conn.Transport = "tcp"
	}

	// Version + auth
	switch dev.Version {
	case "1", "v1":
		conn.Version = gosnmp.Version1
		conn.Community = dev.Community
	case "3", "v3":
		conn.Version = gosnmp.Version3
		conn.SecurityModel = gosnmp.UserSecurityModel
		usmParams := &gosnmp.UsmSecurityParameters{
			UserName: dev.V3Username,
		}

		switch dev.V3SecurityLevel {
		case "authPriv":
			conn.MsgFlags = gosnmp.AuthPriv
			usmParams.AuthenticationPassphrase = dev.V3AuthPassword
			usmParams.PrivacyPassphrase = dev.V3PrivPassword
			usmParams.AuthenticationProtocol = mapAuthProtocol(dev.V3AuthProtocol)
			usmParams.PrivacyProtocol = mapPrivProtocol(dev.V3PrivProtocol)
		case "authNoPriv":
			conn.MsgFlags = gosnmp.AuthNoPriv
			usmParams.AuthenticationPassphrase = dev.V3AuthPassword
			usmParams.AuthenticationProtocol = mapAuthProtocol(dev.V3AuthProtocol)
		default: // noAuthNoPriv
			conn.MsgFlags = gosnmp.NoAuthNoPriv
		}

		conn.SecurityParameters = usmParams
	default: // "2c", "v2c", "2", ""
		conn.Version = gosnmp.Version2c
		conn.Community = dev.Community
	}

	if err := conn.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s:%d: %w", dev.Ip, dev.Port, err)
	}

	return conn, nil
}

func mapAuthProtocol(p string) gosnmp.SnmpV3AuthProtocol {
	switch p {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA-1":
		return gosnmp.SHA
	case "SHA-224":
		return gosnmp.SHA224
	case "SHA-256":
		return gosnmp.SHA256
	case "SHA-384":
		return gosnmp.SHA384
	case "SHA-512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func mapPrivProtocol(p string) gosnmp.SnmpV3PrivProtocol {
	switch p {
	case "DES":
		return gosnmp.DES
	case "AES", "AES-128":
		return gosnmp.AES
	case "AES-192":
		return gosnmp.AES192
	case "AES-256":
		return gosnmp.AES256
	case "AES-192-C":
		return gosnmp.AES192C
	case "AES-256-C":
		return gosnmp.AES256C
	default:
		return gosnmp.AES
	}
}

// snmpValueToString converts a gosnmp PDU value to a string.
func snmpValueToString(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.Integer:
		return fmt.Sprintf("%d", gosnmp.ToBigInt(pdu.Value).Int64())
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		// Try UTF-8 first
		for _, c := range b {
			if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
				// Non-printable - return hex
				return formatHex(b)
			}
		}
		return string(b)
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string)
	case gosnmp.Counter32:
		return fmt.Sprintf("%d", pdu.Value.(uint))
	case gosnmp.Counter64:
		return fmt.Sprintf("%d", pdu.Value.(uint64))
	case gosnmp.Gauge32:
		return fmt.Sprintf("%d", pdu.Value.(uint))
	case gosnmp.TimeTicks:
		return fmt.Sprintf("%d", pdu.Value.(uint32))
	case gosnmp.IPAddress:
		return pdu.Value.(string)
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return "null"
	case gosnmp.Opaque:
		return formatHex(pdu.Value.([]byte))
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func formatHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ":"
		}
		result += p
	}
	return result
}
