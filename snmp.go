// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

const snmpMaxOIDsPerGet = 60

// System-group OIDs a credential probe reads to prove a candidate and feed
// device identification.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
)

// Wire bounds for the system strings a probe reports. The server rejects
// over-length values and drops the result, so the agent truncates here.
const (
	probeMaxOIDBytes   = 255
	probeMaxNameBytes  = 255
	probeMaxDescrBytes = 2048
)

// Probe pacing defaults and floors. The inter-attempt floor keeps a probe
// from hammering a device when the server asks for no delay.
const (
	defaultProbeAttemptTimeout = 10 * time.Second
	minProbeAttemptDelay       = 250 * time.Millisecond
	maxProbeAttemptRetries     = 10
)

// snmpQuerier abstracts SNMP operations for testability.
type snmpQuerier interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	WalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
	BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
	Walk(rootOid string, walkFn gosnmp.WalkFunc) error
	BulkWalk(rootOid string, walkFn gosnmp.WalkFunc) error
}

// snmpDial connects to the job's SNMP device and returns a querier + close
// function. The job's snmp_timeout_ms/snmp_retries override the connection
// defaults; zero keeps them.
var snmpDial = func(ctx context.Context, job *pb.AgentJob) (snmpQuerier, func(), error) {
	conn, err := newSnmpConn(ctx, job.SnmpDevice)
	if err != nil {
		return nil, nil, err
	}
	if job.SnmpTimeoutMs > 0 {
		conn.Timeout = time.Duration(job.SnmpTimeoutMs) * time.Millisecond
	}
	if job.SnmpRetries > 0 {
		conn.Retries = int(job.SnmpRetries)
	}
	return &rateLimitedQuerier{ctx: ctx, q: conn}, func() { _ = conn.Conn.Close() }, nil
}

// closeOnCancellation interrupts gosnmp even if a transport path does not
// observe GoSNMP.Context while blocked in socket I/O.
func closeOnCancellation(ctx context.Context, closeFn func()) func() {
	var once sync.Once
	closeOnce := func() { once.Do(closeFn) }
	stop := context.AfterFunc(ctx, closeOnce)
	return func() {
		stop()
		closeOnce()
	}
}

// executeSnmpJob runs SNMP GET/WALK queries for a job and sends results.
//
// The job's deadline_ms bounds the whole run: when it expires (or the session
// context is cancelled) the walk stops and whatever was collected ships as a
// partial result naming the roots that completed, so the server reconciles
// only those stages instead of losing minutes of work. Results are sent on
// the agent context — not the job context — so a cancelled job's partial
// result still reaches the spool and survives a reconnect.
func executeSnmpJob(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		sendResult(out.agentCtx, out, "result", emptySnmpResult(job), job.JobId)
		return
	}

	if job.DeadlineMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(job.DeadlineMs)*time.Millisecond)
		defer cancel()
	}

	conn, closeFn, err := snmpDial(ctx, job)
	if err != nil {
		slog.Error("snmp connect", "job_id", job.JobId, "device", dev.Ip, "error", err)
		sendResult(out.agentCtx, out, "result", emptySnmpResult(job), job.JobId)
		return
	}
	defer closeOnCancellation(ctx, closeFn)()

	// Values accumulate per walk root so an oversized result can be split
	// along root boundaries and a cancelled job can name the roots that
	// finished. GET batches share one bucket: their OIDs are scalar reads,
	// not subtree walks, so they are not listed in completed_roots.
	getValues := make(map[string]string)
	buckets := []snmpResultBucket{{label: "", values: getValues}}

	var completedRoots []string
	var queryErrors []string
	cancelled := false
	for _, q := range job.Queries {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		switch q.QueryType {
		case pb.QueryType_GET:
			for batch := range slices.Chunk(q.Oids, snmpMaxOIDsPerGet) {
				if ctx.Err() != nil {
					cancelled = true
					break
				}
				if err := snmpGetInto(conn, dev, batch, getValues); err != nil && ctx.Err() == nil {
					queryErrors = append(queryErrors, fmt.Sprintf("GET: %v", err))
				}
			}
		case pb.QueryType_WALK:
			// SNMPv1 doesn't support GETBULK, use GETNEXT-based WalkAll instead
			useV1Walk := isSnmpV1(dev.Version)
			for _, baseOID := range q.Oids {
				if ctx.Err() != nil {
					cancelled = true
					break
				}
				root := canonicalOID(baseOID)
				values := make(map[string]string)
				var results []gosnmp.SnmpPDU
				if useV1Walk {
					results, err = conn.WalkAll(baseOID)
				} else {
					results, err = conn.BulkWalkAll(baseOID)
				}
				for _, v := range results {
					if !snmpValueUsable(v) {
						continue
					}
					values[canonicalOID(v.Name)] = snmpValueToString(v)
				}
				buckets = append(buckets, snmpResultBucket{label: root, values: values})
				if err != nil {
					if ctx.Err() != nil {
						cancelled = true
						break
					}
					slog.Warn("snmp walk failed", "device", dev.Ip, "oid", baseOID, "error", err)
					queryErrors = append(queryErrors, fmt.Sprintf("%s: %v", root, err))
					continue
				}
				completedRoots = append(completedRoots, root)
			}
		}
		if cancelled {
			break
		}
	}

	partial := cancelled || ctx.Err() != nil
	if partial {
		slog.Warn("snmp job ended early, shipping partial result",
			"job_id", job.JobId,
			"completed_roots", len(completedRoots),
			"error", ctx.Err())
	} else {
		slog.Info("snmp job complete", "job_id", job.JobId, "roots", len(completedRoots))
	}

	frames := buildSnmpResultFrames(job, buckets, completedRoots, partial)
	for _, frame := range frames {
		frame.DiscoveryPhase = job.DiscoveryPhase
		sendResult(out.agentCtx, out, "result", frame, job.JobId)
	}
	if len(queryErrors) > 0 && ctx.Err() == nil {
		sendResult(out.agentCtx, out, "error", &pb.AgentError{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Message:   "SNMP query failed: " + strings.Join(queryErrors, "; "),
			Timestamp: time.Now().Unix(),
		}, job.JobId)
	}
}

func emptySnmpResult(job *pb.AgentJob) *pb.SnmpResult {
	return &pb.SnmpResult{
		DeviceId:       job.DeviceId,
		JobType:        job.JobType,
		JobId:          job.JobId,
		OidValues:      make(map[string]string),
		Timestamp:      time.Now().Unix(),
		Final:          true,
		DiscoveryPhase: job.DiscoveryPhase,
	}
}

// defaultMaxResultBytes bounds the base64 result payload when the job does
// not carry max_result_bytes. The server rejects binary payloads over 10 MiB,
// so the default stays under it.
const defaultMaxResultBytes = 8 << 20

// maxResultPayloadHeadroom covers the channelMsg JSON envelope around the
// base64 payload and the frame metadata fields (completed_roots, sequence,
// flags) that oidEntrySize does not account for.
const maxResultPayloadHeadroom = 4096

// snmpResultBucket groups the OID values collected under one walk root. The
// empty label is the shared GET bucket.
type snmpResultBucket struct {
	label  string
	values map[string]string
}

// getBucketTruncatedLabel names the shared GET bucket in truncated_roots:
// GET OIDs are scalar reads with no walk root, so a sentinel marks the drop.
const getBucketTruncatedLabel = "<get-batch>"

// buildSnmpResultFrames packs the collected buckets into SnmpResult frames
// whose base64 payload stays under the job's max_result_bytes. A result that
// fits ships as one frame with sequence 0; a larger one splits along bucket
// boundaries into frames numbered from 1, the last marked final. A single
// bucket that cannot fit one frame is truncated to what fits and named in
// truncated_roots.
func buildSnmpResultFrames(
	job *pb.AgentJob,
	buckets []snmpResultBucket,
	completedRoots []string,
	partial bool,
) []*pb.SnmpResult {
	maxPayload := int64(job.MaxResultBytes)
	if maxPayload <= 0 {
		maxPayload = defaultMaxResultBytes
	}
	// The bound applies to the base64 payload; keep the decoded protobuf
	// under three quarters of it, minus the envelope/metadata headroom.
	maxDecoded := maxPayload*3/4 - maxResultPayloadHeadroom
	if maxDecoded < 1024 {
		maxDecoded = 1024
	}

	newFrame := func() *pb.SnmpResult {
		return &pb.SnmpResult{
			DeviceId:       job.DeviceId,
			JobType:        job.JobType,
			JobId:          job.JobId,
			OidValues:      make(map[string]string),
			Timestamp:      time.Now().Unix(),
			Partial:        partial,
			CompletedRoots: completedRoots,
		}
	}

	var frames []*pb.SnmpResult
	var truncated []string
	frame := newFrame()
	frameSize := int64(0)
	flush := func() {
		frames = append(frames, frame)
		frame = newFrame()
		frameSize = 0
	}

	for _, bucket := range buckets {
		bucketSize := int64(0)
		for k, v := range bucket.values {
			bucketSize += oidEntrySize(k, v)
		}
		if bucketSize <= maxDecoded {
			// Whole bucket fits a frame; start a new one when it does not
			// fit alongside what is already packed.
			if frameSize+bucketSize > maxDecoded && frameSize > 0 {
				flush()
			}
			for k, v := range bucket.values {
				frame.OidValues[k] = v
			}
			frameSize += bucketSize
			continue
		}
		// The bucket alone exceeds a frame: pack only the entries that fit
		// into a dedicated frame and flag the root as truncated. The shared GET
		// bucket has no walk root to name, so it reports a sentinel — silently
		// dropping its overflow would ship a result that looks complete.
		label := bucket.label
		if label == "" {
			label = getBucketTruncatedLabel
		}
		truncated = append(truncated, label)
		if frameSize > 0 {
			flush()
		}
		dropped := 0
		for k, v := range bucket.values {
			entry := oidEntrySize(k, v)
			if frameSize+entry > maxDecoded {
				dropped++
				continue
			}
			frame.OidValues[k] = v
			frameSize += entry
		}
		if dropped > 0 {
			slog.Warn("snmp result truncated to fit max_result_bytes",
				"job_id", job.JobId, "root", label, "dropped", dropped)
		}
		flush()
	}
	if frameSize > 0 || len(frames) == 0 {
		flush()
	}

	if len(frames) == 1 {
		// Unsplit results keep sequence 0 so the server treats them exactly
		// like a legacy single-frame result.
		frames[0].Final = true
	} else {
		for i, f := range frames {
			f.Sequence = uint32(i + 1)
			f.Final = i == len(frames)-1
		}
	}
	for _, f := range frames {
		f.TruncatedRoots = truncated
	}
	return frames
}

// oidEntrySize returns the encoded size of one oid_values map entry: a
// length-delimited field 3 record wrapping the key/value entry message.
func oidEntrySize(key, value string) int64 {
	entry := int64(1 + varintLen(len(key)) + len(key) + 1 + varintLen(len(value)) + len(value))
	return int64(1+varintLen(int(entry))) + entry
}

func varintLen(v int) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// isSnmpV1 reports whether a device speaks SNMPv1, which has no GETBULK.
func isSnmpV1(version string) bool { return version == "1" || version == "v1" }

// snmpGetInto records one GET batch. gosnmp reports an SNMP error-status
// response through result.Error with err == nil, and SNMPv1 answers a batch
// containing any unknown OID with noSuchName plus every request varbind echoed
// back as Null - so the batch is halved down to single OIDs to recover the
// values that do resolve. tooBig is split for the same reason: the device
// cannot fit the response in one PDU.
func snmpGetInto(conn snmpQuerier, dev *pb.SnmpDevice, oids []string, into map[string]string) error {
	result, err := conn.Get(oids)
	if err != nil {
		slog.Warn("snmp get failed", "device", dev.Ip, "oids", len(oids), "error", err)
		return err
	}

	switch result.Error {
	case gosnmp.NoError:
		for _, v := range result.Variables {
			if !snmpValueUsable(v) {
				continue
			}
			into[canonicalOID(v.Name)] = snmpValueToString(v)
		}
		return nil
	case gosnmp.NoSuchName, gosnmp.TooBig:
		if len(oids) == 1 {
			slog.Debug("snmp get oid skipped", "device", dev.Ip, "oid", oids[0], "status", result.Error, "error_index", result.ErrorIndex)
			return nil
		}
		slog.Warn("snmp get batch split", "device", dev.Ip, "batch_size", len(oids), "status", result.Error, "error_index", result.ErrorIndex)
		mid := len(oids) / 2
		return errors.Join(
			snmpGetInto(conn, dev, oids[:mid], into),
			snmpGetInto(conn, dev, oids[mid:], into),
		)
	default:
		slog.Warn("snmp get error status", "device", dev.Ip, "batch_size", len(oids), "status", result.Error, "error_index", result.ErrorIndex)
		return fmt.Errorf("status %s at index %d", result.Error, result.ErrorIndex)
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

// systemValues maps a GET response's varbinds by canonical OID, skipping
// unusable values (Null, NoSuchObject, NoSuchInstance, EndOfMibView).
func systemValues(packet *gosnmp.SnmpPacket) map[string]string {
	values := make(map[string]string, len(packet.Variables))
	for _, pdu := range packet.Variables {
		if snmpValueUsable(pdu) {
			values[canonicalOID(pdu.Name)] = snmpValueToString(pdu)
		}
	}
	return values
}

// truncateBytes shortens s to at most n bytes without splitting a UTF-8
// sequence: the wire contract bounds these fields in bytes, and a mid-rune
// cut would fail the server's UTF-8 validation anyway.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n]
}

// sleepContext waits for d or returns early when ctx is cancelled.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// executeCredentialTest tests SNMP credentials by reading the system group.
func executeCredentialTest(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
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

	conn, closeFn, err := snmpDial(ctx, job)
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
	defer closeOnCancellation(ctx, closeFn)()

	// Prove the credential with sysDescr.0 alone: under SNMPv1 one missing
	// object fails the whole PDU with noSuchName, so bundling the identity
	// OIDs here would report a working credential as failed.
	packet, err := conn.Get([]string{oidSysDescr})
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

	if packet.Error != gosnmp.NoError {
		result := &pb.CredentialTestResult{
			TestId:       job.JobId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("SNMP test failed: status %v (error index %d)", packet.Error, packet.ErrorIndex),
			Timestamp:    timestamp,
		}
		slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
		sendResult(ctx, out, "credential_test_result", result, job.JobId)
		return
	}

	values := systemValues(packet)

	// Best effort: sysObjectID/sysName enrich the result for device
	// identification but their absence never fails the credential proof.
	// snmpGetInto halves a noSuchName batch to single OIDs, so a device
	// missing sysName still yields its sysObjectID.
	_ = snmpGetInto(conn, dev, []string{oidSysObjectID, oidSysName}, values)
	// A successful GET proves the credentials work even when the system
	// values are unavailable.
	result := &pb.CredentialTestResult{
		TestId:            job.JobId,
		Success:           true,
		SystemDescription: truncateBytes(values[oidSysDescr], probeMaxDescrBytes),
		SysObjectId:       truncateBytes(canonicalOID(values[oidSysObjectID]), probeMaxOIDBytes),
		SysName:           truncateBytes(values[oidSysName], probeMaxNameBytes),
		Timestamp:         timestamp,
	}
	slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
	sendResult(ctx, out, "credential_test_result", result, job.JobId)
}

// probeCandidate performs one probe attempt: dial the candidate and prove
// the credential with a sysDescr.0 GET within the attempt timeout. The
// timeout bounds the whole exchange, including gosnmp's own retries.
//
// The proof GET asks for sysDescr.0 alone: under SNMPv1 a single missing
// object fails the whole PDU with noSuchName, so bundling the identity
// OIDs into the proof would report a working credential as failed. The
// sysObjectID/sysName GET is a second, best-effort exchange — its failure
// yields empty identity values, not a rejected credential.
func probeCandidate(ctx context.Context, dev *pb.SnmpDevice, timeout time.Duration) (map[string]string, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, closeFn, err := snmpDial(attemptCtx, &pb.AgentJob{SnmpDevice: dev})
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer closeOnCancellation(attemptCtx, closeFn)()

	packet, err := conn.Get([]string{oidSysDescr})
	if err != nil {
		return nil, fmt.Errorf("SNMP probe failed: %w", err)
	}
	if packet.Error != gosnmp.NoError {
		return nil, fmt.Errorf("SNMP probe failed: status %v (error index %d)", packet.Error, packet.ErrorIndex)
	}

	values := systemValues(packet)

	// Best effort: identity OIDs enrich the result but never fail the
	// proof. snmpGetInto halves a noSuchName batch to single OIDs, so a
	// device missing sysName still yields its sysObjectID.
	_ = snmpGetInto(conn, dev, []string{oidSysObjectID, oidSysName}, values)

	return values, nil
}

// executeCredentialProbe tries each candidate credential in order against
// the target and reports which index answered, along with the probed
// device's system values so the server can classify it and pin the working
// credential set.
func executeCredentialProbe(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	probe := job.CredentialProbe
	started := time.Now()
	result := &pb.CredentialProbeResult{ProbeId: job.JobId, MatchedIndex: -1}

	send := func() {
		result.DurationMs = uint32(time.Since(started).Milliseconds())
		result.Timestamp = time.Now().Unix()
		slog.Info("credential probe complete",
			"probe_id", result.ProbeId,
			"matched_index", result.MatchedIndex,
			"duration_ms", result.DurationMs)
		sendResult(ctx, out, "credential_probe_result", result, job.JobId)
	}

	if probe == nil || len(probe.Candidates) == 0 {
		result.ErrorMessage = "missing probe configuration"
		send()
		return
	}

	timeout := defaultProbeAttemptTimeout
	if probe.AttemptTimeoutMs > 0 {
		timeout = time.Duration(probe.AttemptTimeoutMs) * time.Millisecond
	}
	delay := max(time.Duration(probe.InterAttemptDelayMs)*time.Millisecond, minProbeAttemptDelay)
	attempts := 1 + int(min(probe.AttemptRetries, maxProbeAttemptRetries))

	first := true
	matched := false
	for i, candidate := range probe.Candidates {
		for attempt := 0; attempt < attempts; attempt++ {
			if ctx.Err() != nil {
				return
			}
			if !first && !sleepContext(ctx, delay) {
				return
			}
			first = false

			values, err := probeCandidate(ctx, candidate, timeout)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !matched {
					result.ErrorMessage = err.Error()
				}
				continue
			}
			// The first match wins: candidates are priority-ordered, so the
			// earliest success is the credential the server should pin even
			// when the probe keeps validating the rest of the list.
			if !matched {
				result.MatchedIndex = int32(i)
				result.SysObjectId = truncateBytes(canonicalOID(values[oidSysObjectID]), probeMaxOIDBytes)
				result.SysDescr = truncateBytes(values[oidSysDescr], probeMaxDescrBytes)
				result.SysName = truncateBytes(values[oidSysName], probeMaxNameBytes)
				result.ErrorMessage = ""
				matched = true
			}

			if probe.StopOnFirstSuccess {
				send()
				return
			}
			break
		}
	}

	if !matched {
		slog.Info("credential probe found no working credential",
			"probe_id", result.ProbeId,
			"candidates", len(probe.Candidates))
	}
	send()
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
		MaxRepetitions: 25,
		Context:        ctx,
	}
	// gosnmp invokes OnSent after every transmitted packet, including
	// retries, so the process-wide token bucket paces real wire traffic.
	conn.OnSent = snmpSentHook(snmpPDUs)

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

const oidIfPhysAddress = "1.3.6.1.2.1.2.2.1.6"

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
		if strings.HasPrefix(canonicalOID(pdu.Name), oidIfPhysAddress+".") {
			return formatHex(b)
		}
		if !utf8.Valid(b) {
			return formatHex(b)
		}
		for _, c := range b {
			if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7f {
				return formatHex(b)
			}
		}
		return string(b)
	case gosnmp.ObjectIdentifier:
		switch value := pdu.Value.(type) {
		case string:
			return value
		case []byte:
			return formatHex(value)
		default:
			return fmt.Sprintf("%v", value)
		}
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
