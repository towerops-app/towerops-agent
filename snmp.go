package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

const snmpMaxOIDsPerGet = 60

// snmpQuerier abstracts SNMP operations for testability.
type snmpQuerier interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	WalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
	BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
}

// snmpDial connects to an SNMP device and returns a querier + close function.
var snmpDial = func(dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
	conn, err := newSnmpConn(dev)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { _ = conn.Conn.Close() }, nil
}

// executeSnmpJob runs SNMP GET/WALK queries for a job and sends results.
func executeSnmpJob(job *pb.AgentJob, resultCh chan<- *pb.SnmpResult) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		return
	}

	conn, closeFn, err := snmpDial(dev)
	if err != nil {
		slog.Error("snmp connect", "job_id", job.JobId, "device", dev.Ip, "error", err)
		return
	}
	defer closeFn()

	totalOIDs := 0
	for _, q := range job.Queries {
		totalOIDs += len(q.Oids)
	}
	oidValues := make(map[string]string, totalOIDs)

	for _, q := range job.Queries {
		switch q.QueryType {
		case pb.QueryType_GET:
			for i := 0; i < len(q.Oids); i += snmpMaxOIDsPerGet {
				end := i + snmpMaxOIDsPerGet
				if end > len(q.Oids) {
					end = len(q.Oids)
				}
				batch := q.Oids[i:end]
				result, err := conn.Get(batch)
				if err != nil {
					slog.Warn("snmp get failed", "device", dev.Ip, "oids", len(batch), "error", err)
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
			// SNMPv1 doesn't support GETBULK, use GETNEXT-based WalkAll instead
			useV1Walk := dev.Version == "1" || dev.Version == "v1"
			for _, baseOID := range q.Oids {
				var results []gosnmp.SnmpPDU
				if useV1Walk {
					results, err = conn.WalkAll(baseOID)
				} else {
					results, err = conn.BulkWalkAll(baseOID)
				}
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

	conn, closeFn, err := snmpDial(dev)
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
	defer closeFn()

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
		Target:         dev.Ip,
		Port:           uint16(dev.Port),
		Timeout:        10 * time.Second,
		Retries:        2,
		MaxRepetitions: 10,
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
		return strconv.FormatInt(gosnmp.ToBigInt(pdu.Value).Int64(), 10)
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		if !utf8.Valid(b) {
			return formatHex(b)
		}
		for _, c := range b {
			if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
				return formatHex(b)
			}
		}
		return string(b)
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string)
	case gosnmp.Counter32:
		return strconv.FormatUint(uint64(pdu.Value.(uint)), 10)
	case gosnmp.Counter64:
		return strconv.FormatUint(pdu.Value.(uint64), 10)
	case gosnmp.Gauge32:
		return strconv.FormatUint(uint64(pdu.Value.(uint)), 10)
	case gosnmp.TimeTicks:
		return strconv.FormatUint(uint64(pdu.Value.(uint32)), 10)
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
	h := hex.EncodeToString(b)
	var buf strings.Builder
	buf.Grow(len(h) + len(b) - 1)
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			buf.WriteByte(':')
		}
		buf.WriteByte(h[i])
		buf.WriteByte(h[i+1])
	}
	return buf.String()
}
