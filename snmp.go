// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
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
	Walk(rootOid string, walkFn gosnmp.WalkFunc) error
	BulkWalk(rootOid string, walkFn gosnmp.WalkFunc) error
}

// snmpDial connects to an SNMP device and returns a querier + close function.
var snmpDial = func(ctx context.Context, dev *pb.SnmpDevice) (snmpQuerier, func(), error) {
	conn, err := newSnmpConn(ctx, dev)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { _ = conn.Conn.Close() }, nil
}

// executeSnmpJob runs SNMP GET/WALK queries for a job and sends results.
func executeSnmpJob(ctx context.Context, job *pb.AgentJob, out resultQueue) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		sendResult(ctx, out, "result", emptySnmpResult(job), job.JobId)
		return
	}

	conn, closeFn, err := snmpDial(ctx, dev)
	if err != nil {
		slog.Error("snmp connect", "job_id", job.JobId, "device", dev.Ip, "error", err)
		sendResult(ctx, out, "result", emptySnmpResult(job), job.JobId)
		return
	}
	defer closeFn()

	totalOIDs := 0
	for _, q := range job.Queries {
		totalOIDs += len(q.Oids)
	}
	oidValues := make(map[string]string, totalOIDs)

	cancelled := false
	for _, q := range job.Queries {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		switch q.QueryType {
		case pb.QueryType_GET:
			for batch := range slices.Chunk(q.Oids, snmpMaxOIDsPerGet) {
				snmpGetInto(conn, dev, batch, oidValues)
			}
		case pb.QueryType_WALK:
			// SNMPv1 doesn't support GETBULK, use GETNEXT-based WalkAll instead
			useV1Walk := isSnmpV1(dev.Version)
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
					if !snmpValueUsable(v) {
						continue
					}
					oidValues[canonicalOID(v.Name)] = snmpValueToString(v)
				}
			}
		}
	}

	if cancelled {
		slog.Warn("snmp job cancelled, sending partial result", "job_id", job.JobId, "oids", len(oidValues))
	}

	result := &pb.SnmpResult{
		DeviceId:  job.DeviceId,
		JobType:   job.JobType,
		JobId:     job.JobId,
		OidValues: oidValues,
		Timestamp: time.Now().Unix(),
	}

	slog.Info("snmp job complete", "job_id", job.JobId, "oids", len(oidValues))
	sendResult(ctx, out, "result", result, job.JobId)
}

func emptySnmpResult(job *pb.AgentJob) *pb.SnmpResult {
	return &pb.SnmpResult{
		DeviceId:  job.DeviceId,
		JobType:   job.JobType,
		JobId:     job.JobId,
		OidValues: make(map[string]string),
		Timestamp: time.Now().Unix(),
	}
}

// isSnmpV1 reports whether a device speaks SNMPv1, which has no GETBULK.
func isSnmpV1(version string) bool { return version == "1" || version == "v1" }

// snmpGetInto records one GET batch. gosnmp reports an SNMP error-status
// response through result.Error with err == nil, and SNMPv1 answers a batch
// containing any unknown OID with noSuchName plus every request varbind echoed
// back as Null — so the batch is halved down to single OIDs to recover the
// values that do resolve. tooBig is split for the same reason: the device
// cannot fit the response in one PDU.
func snmpGetInto(conn snmpQuerier, dev *pb.SnmpDevice, oids []string, into map[string]string) {
	result, err := conn.Get(oids)
	if err != nil {
		slog.Warn("snmp get failed", "device", dev.Ip, "oids", len(oids), "error", err)
		return
	}

	switch result.Error {
	case gosnmp.NoError:
		for _, v := range result.Variables {
			if !snmpValueUsable(v) {
				continue
			}
			into[canonicalOID(v.Name)] = snmpValueToString(v)
		}
	case gosnmp.NoSuchName, gosnmp.TooBig:
		if len(oids) == 1 {
			slog.Debug("snmp get oid skipped", "device", dev.Ip, "oid", oids[0], "status", result.Error, "error_index", result.ErrorIndex)
			return
		}
		slog.Warn("snmp get batch split", "device", dev.Ip, "batch_size", len(oids), "status", result.Error, "error_index", result.ErrorIndex)
		mid := len(oids) / 2
		snmpGetInto(conn, dev, oids[:mid], into)
		snmpGetInto(conn, dev, oids[mid:], into)
	default:
		slog.Warn("snmp get error status", "device", dev.Ip, "batch_size", len(oids), "status", result.Error, "error_index", result.ErrorIndex)
	}
}

func snmpValueUsable(pdu gosnmp.SnmpPDU) bool {
	return pdu.Type != gosnmp.Null &&
		pdu.Type != gosnmp.NoSuchObject &&
		pdu.Type != gosnmp.NoSuchInstance &&
		pdu.Type != gosnmp.EndOfMibView
}

func canonicalOID(oid string) string {
	return strings.TrimPrefix(oid, ".")
}

// executeCredentialTest tests SNMP credentials by reading sysDescr.0.
func executeCredentialTest(ctx context.Context, job *pb.AgentJob, out resultQueue) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		result := &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: "missing device configuration",
			Timestamp:    time.Now().Unix(),
		}
		slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
		sendResult(ctx, out, "credential_test_result", result, job.JobId)
		return
	}

	conn, closeFn, err := snmpDial(ctx, dev)
	timestamp := time.Now().Unix()

	if err != nil {
		result := &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("connection failed: %v", err),
			Timestamp:    timestamp,
		}
		slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
		sendResult(ctx, out, "credential_test_result", result, job.JobId)
		return
	}
	defer closeFn()

	packet, err := conn.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		result := &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("SNMP test failed: %v", err),
			Timestamp:    timestamp,
		}
		slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
		sendResult(ctx, out, "credential_test_result", result, job.JobId)
		return
	}

	sysDescr := ""
	if packet.Error != gosnmp.NoError {
		slog.Debug("snmp credential test error status", "device", dev.Ip, "status", packet.Error, "error_index", packet.ErrorIndex)
	} else if len(packet.Variables) > 0 && snmpValueUsable(packet.Variables[0]) {
		sysDescr = snmpValueToString(packet.Variables[0])
	}
	// A successful GET proves the credentials work even when sysDescr is unavailable.

	result := &pb.CredentialTestResult{
		TestId:            job.JobId,
		Success:           true,
		SystemDescription: sysDescr,
		Timestamp:         timestamp,
	}
	slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
	sendResult(ctx, out, "credential_test_result", result, job.JobId)
}

// newSnmpConn creates a gosnmp.GoSNMP connection from protobuf device config.
func newSnmpConn(ctx context.Context, dev *pb.SnmpDevice) (*gosnmp.GoSNMP, error) {
	if dev.Port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", dev.Port)
	}
	port := dev.Port
	if port == 0 {
		port = 161
	}
	conn := &gosnmp.GoSNMP{
		Target:         dev.Ip,
		Port:           uint16(port),
		Timeout:        10 * time.Second,
		Retries:        2,
		MaxRepetitions: 10,
		Context:        ctx,
	}

	// Transport
	if dev.Transport == "tcp" {
		conn.Transport = "tcp"
	}

	// Version + auth
	switch {
	case isSnmpV1(dev.Version):
		conn.Version = gosnmp.Version1
		conn.Community = dev.Community
	case dev.Version == "3" || dev.Version == "v3":
		conn.Version = gosnmp.Version3
		conn.SecurityModel = gosnmp.UserSecurityModel
		usmParams := &gosnmp.UsmSecurityParameters{
			UserName: dev.V3Username,
		}

		switch dev.V3SecurityLevel {
		case "authPriv":
			authProtocol, err := mapAuthProtocol(dev.V3AuthProtocol)
			if err != nil {
				return nil, err
			}
			privProtocol, err := mapPrivProtocol(dev.V3PrivProtocol)
			if err != nil {
				return nil, err
			}
			conn.MsgFlags = gosnmp.AuthPriv
			usmParams.AuthenticationPassphrase = dev.V3AuthPassword
			usmParams.PrivacyPassphrase = dev.V3PrivPassword
			usmParams.AuthenticationProtocol = authProtocol
			usmParams.PrivacyProtocol = privProtocol
		case "authNoPriv":
			authProtocol, err := mapAuthProtocol(dev.V3AuthProtocol)
			if err != nil {
				return nil, err
			}
			conn.MsgFlags = gosnmp.AuthNoPriv
			usmParams.AuthenticationPassphrase = dev.V3AuthPassword
			usmParams.AuthenticationProtocol = authProtocol
		default: // noAuthNoPriv
			conn.MsgFlags = gosnmp.NoAuthNoPriv
		}

		conn.SecurityParameters = usmParams
	default: // "2c", "v2c", "2", ""
		conn.Version = gosnmp.Version2c
		conn.Community = dev.Community
	}

	if err := conn.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s:%d: %w", dev.Ip, port, err)
	}

	return conn, nil
}

func mapAuthProtocol(p string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch p {
	case "MD5":
		return gosnmp.MD5, nil
	case "", "SHA", "SHA-1":
		return gosnmp.SHA, nil
	case "SHA-224":
		return gosnmp.SHA224, nil
	case "SHA-256":
		return gosnmp.SHA256, nil
	case "SHA-384":
		return gosnmp.SHA384, nil
	case "SHA-512":
		return gosnmp.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported SNMPv3 auth protocol %q", p)
	}
}

func mapPrivProtocol(p string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch p {
	case "DES":
		return gosnmp.DES, nil
	case "", "AES", "AES-128":
		return gosnmp.AES, nil
	case "AES-192":
		return gosnmp.AES192, nil
	case "AES-256":
		return gosnmp.AES256, nil
	case "AES-192-C":
		return gosnmp.AES192C, nil
	case "AES-256-C":
		return gosnmp.AES256C, nil
	default:
		return 0, fmt.Errorf("unsupported SNMPv3 privacy protocol %q", p)
	}
}

// snmpValueToString converts a gosnmp PDU value to a string.
func snmpValueToString(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Counter64, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		return gosnmp.ToBigInt(pdu.Value).String()
	case gosnmp.OctetString:
		b, ok := pdu.Value.([]byte)
		if !ok {
			return fmt.Sprintf("%v", pdu.Value)
		}
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
		if s, ok := pdu.Value.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", pdu.Value)
	case gosnmp.IPAddress:
		if s, ok := pdu.Value.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", pdu.Value)
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return "null"
	case gosnmp.Opaque:
		if b, ok := pdu.Value.([]byte); ok {
			return formatHex(b)
		}
		return fmt.Sprintf("%v", pdu.Value)
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
