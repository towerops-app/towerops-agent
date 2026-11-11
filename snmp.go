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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

const snmpMaxOIDsPerGet = 60

// snmpMaxRepetitions is the GETBULK max-repetitions the walk loop requests
// per round trip; newSnmpConn configures the connection to the same value.
const snmpMaxRepetitions = 25

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

// snmpQuerier abstracts SNMP request operations for testability. Walks are
// never delegated to gosnmp: its walk functions return a nil error when the
// device answers genErr, tooBig, authorizationError, resourceUnavailable or
// an empty varbind list, so snmpWalkAll runs the GETNEXT/GETBULK loop here
// and inspects every response's error status itself.
type snmpQuerier interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	GetNext(oids []string) (*gosnmp.SnmpPacket, error)
	GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (*gosnmp.SnmpPacket, error)
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
	absentOIDs := 0
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
				start := time.Now()
				absent, err := snmpGetInto(conn, dev, batch, getValues)
				buckets[0].duration += time.Since(start)
				absentOIDs += absent
				if err != nil {
					// A transport may observe the deadline before the context's
					// timer publishes Err. The operation's wrapped error is
					// authoritative too; do not start another request.
					if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
						cancelled = true
						break
					}
					slog.Warn("snmp get failed", "job_id", job.JobId, "device", dev.Ip, "operation", "GET", "error", err)
					queryErrors = append(queryErrors, fmt.Sprintf("GET: %v", err))
				}
			}
		case pb.QueryType_WALK:
			// SNMPv1 has no GETBULK, so its walk runs on GETNEXT.
			useV1Walk := isSnmpV1(dev.Version)
			for _, baseOID := range q.Oids {
				if ctx.Err() != nil {
					cancelled = true
					break
				}
				root := canonicalOID(baseOID)
				values := make(map[string]string)
				start := time.Now()
				results, err := snmpWalkAll(ctx, conn, baseOID, useV1Walk)
				elapsed := time.Since(start)
				for _, v := range results {
					if !snmpValueUsable(v) {
						continue
					}
					values[canonicalOID(v.Name)] = snmpValueToString(v)
				}
				buckets = append(buckets, snmpResultBucket{
					label: root, values: values, completed: err == nil, duration: elapsed,
				})
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
						cancelled = true
						break
					}
					slog.Warn("snmp walk failed", "job_id", job.JobId, "device", dev.Ip, "operation", "WALK", "root", root, "elapsed", elapsed, "error", err)
					queryErrors = append(queryErrors, fmt.Sprintf("WALK %s: %v (elapsed=%s)", root, err, elapsed))
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
	if absentOIDs > 0 {
		// Absent answers are recorded as empty values the server may prune,
		// but the wire cannot tell "object absent" from "OID outside the
		// credential's view" — surface the count so a scoped credential is
		// visible instead of silently pruning rows.
		slog.Warn("snmp job recorded absent OIDs as empty",
			"job_id", job.JobId, "device", dev.Ip, "absent_oids", absentOIDs)
	}

	frames := buildSnmpResultFrames(job, buckets, partial)
	for _, frame := range frames {
		frame.DiscoveryPhase = job.DiscoveryPhase
		sendResult(out.agentCtx, out, "result", frame, job.JobId)
	}
	if len(queryErrors) > 0 && !cancelled && ctx.Err() == nil {
		sendResult(out.agentCtx, out, "error", &pb.AgentError{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Message:   "SNMP query failed: " + strings.Join(queryErrors, "; "),
			Timestamp: time.Now().Unix(),
		}, job.JobId)
	}
}

// snmpGetError identifies the actual failed request, including recovery
// sub-batches, without formatting successful requests or device credentials.
func snmpGetError(oids []string, elapsed time.Duration, err error) error {
	var batch strings.Builder
	first, last := "", ""
	if len(oids) > 0 {
		first, last = canonicalOID(oids[0]), canonicalOID(oids[len(oids)-1])
	}
	for i, oid := range oids {
		if i > 0 {
			batch.WriteString(", ")
		}
		batch.WriteString(canonicalOID(oid))
	}
	return fmt.Errorf("%w (elapsed=%s, batch_count=%d, first=%s, last=%s, batch=[%s])", err, elapsed, len(oids), first, last, batch.String())
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

// maxResultOIDValues matches the server decoder's per-frame map limit.
const maxResultOIDValues = 50_000

// maxResultPayloadHeadroom covers the channelMsg JSON envelope around the
// base64 payload and the scalar frame fields (ids, sequence, flags) that
// oidEntrySize does not account for. rootListsReserve covers the root lists.
const maxResultPayloadHeadroom = 4096

// rootListsReserve bounds the encoded completed_roots and truncated_roots of
// any one frame. A walk label appears at most once in a frame's
// completed_roots and once in the truncated_roots every frame carries; the
// shared GET bucket can only appear in truncated_roots, as its sentinel.
func rootListsReserve(buckets []snmpResultBucket) int64 {
	var reserve int64
	for _, bucket := range buckets {
		if bucket.label == "" {
			reserve += repeatedStringSize(getBucketTruncatedLabel)
			continue
		}
		reserve += 2 * repeatedStringSize(bucket.label)
	}
	return reserve
}

// repeatedStringSize is the encoded size of one element of a repeated
// string field numbered below 16: a one-byte tag, the length, the bytes.
func repeatedStringSize(s string) int64 {
	return int64(1 + varintLen(len(s)) + len(s))
}

// snmpResultBucket groups the OID values collected under one walk root. The
// empty label is the shared GET bucket. completed marks roots whose walk
// finished — a failed walk still ships its best-effort bucket but must not
// claim the root. duration includes the requests and value conversion, and is
// apportioned by entry count if one operation spans several frames.
type snmpResultBucket struct {
	label     string
	values    map[string]string
	completed bool
	duration  time.Duration
}

// getBucketTruncatedLabel names the shared GET bucket in truncated_roots:
// GET OIDs are scalar reads with no walk root, so a sentinel marks the drop.
const getBucketTruncatedLabel = "<get-batch>"

// buildSnmpResultFrames packs the collected buckets into SnmpResult frames
// whose base64 payload stays under the job's max_result_bytes and whose maps
// stay within the server's entry limit. Large entry counts split losslessly;
// buckets exceeding the byte budget retain explicit truncation semantics.
func buildSnmpResultFrames(
	job *pb.AgentJob,
	buckets []snmpResultBucket,
	partial bool,
) []*pb.SnmpResult {
	maxPayload := int64(job.MaxResultBytes)
	if maxPayload <= 0 {
		maxPayload = defaultMaxResultBytes
	}
	// The bound applies to the base64 payload; keep the decoded protobuf
	// under three quarters of it, minus the envelope/metadata headroom.
	maxDecoded := maxPayload*3/4 - maxResultPayloadHeadroom - rootListsReserve(buckets)
	if maxDecoded < 1024 {
		maxDecoded = 1024
	}

	newFrame := func() *pb.SnmpResult {
		return &pb.SnmpResult{
			DeviceId:  job.DeviceId,
			JobType:   job.JobType,
			JobId:     job.JobId,
			OidValues: make(map[string]string),
			Timestamp: time.Now().Unix(),
			Partial:   partial,
		}
	}

	var frames []*pb.SnmpResult
	var truncated []string
	frame := newFrame()
	frameSize := int64(0)
	frameDuration := time.Duration(0)
	// frameRoots names the completed walk roots packed into the current
	// frame — the server unions them across arrived frames, so a lost frame
	// cannot claim a root whose bucket never arrived.
	var frameRoots []string
	flush := func() {
		frame.CompletedRoots = frameRoots
		frame.DurationMs = snmpDurationMillis(frameDuration)
		frames = append(frames, frame)
		frame = newFrame()
		frameSize = 0
		frameDuration = 0
		frameRoots = nil
	}

	for _, bucket := range buckets {
		bucketSize := int64(0)
		for k, v := range bucket.values {
			bucketSize += oidEntrySize(k, v)
		}
		if bucketSize <= maxDecoded {
			// Keep a whole bucket together when possible. A bucket exceeding
			// the entry cap spans frames, claiming its root only on the tail.
			if (frameSize+bucketSize > maxDecoded ||
				len(frame.OidValues)+len(bucket.values) > maxResultOIDValues) && frameSize > 0 {
				flush()
			}
			if len(bucket.values) > maxResultOIDValues {
				remainingValues := len(bucket.values)
				remainingDuration := bucket.duration
				pieceValues := 0
				for k, v := range bucket.values {
					if len(frame.OidValues) == maxResultOIDValues {
						// Attribute only this piece of the walk, retaining the
						// remainder for later frames without copying the payload.
						pieceDuration := remainingDuration/time.Duration(remainingValues)*time.Duration(pieceValues) +
							remainingDuration%time.Duration(remainingValues)*time.Duration(pieceValues)/time.Duration(remainingValues)
						frameDuration += pieceDuration
						remainingDuration -= pieceDuration
						remainingValues -= pieceValues
						pieceValues = 0
						flush()
					}
					frame.OidValues[k] = v
					frameSize += oidEntrySize(k, v)
					pieceValues++
				}
				frameDuration += remainingDuration
			} else {
				frameDuration += bucket.duration
				for k, v := range bucket.values {
					frame.OidValues[k] = v
				}
				frameSize += bucketSize
			}
			if bucket.completed && bucket.label != "" {
				frameRoots = append(frameRoots, bucket.label)
			}
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
		frameDuration += bucket.duration
		dropped := 0
		for k, v := range bucket.values {
			entry := oidEntrySize(k, v)
			if frameSize+entry > maxDecoded || len(frame.OidValues) == maxResultOIDValues {
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
		if bucket.completed && bucket.label != "" {
			frameRoots = append(frameRoots, bucket.label)
		}
		flush()
	}
	if frameSize > 0 || len(frameRoots) > 0 || len(frames) == 0 {
		flush()
	} else if frameDuration > 0 {
		// Empty failed roots have no frame of their own, but their request
		// time still belongs to the last result of this job.
		last := frames[len(frames)-1]
		last.DurationMs = snmpDurationMillis(time.Duration(last.DurationMs)*time.Millisecond + frameDuration)
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

// snmpDurationMillis reserves zero for unmeasured work. Very fast frames still
// report one millisecond; long-running work saturates the wire's uint32 field.
func snmpDurationMillis(elapsed time.Duration) uint32 {
	if elapsed <= 0 {
		return 0
	}
	return uint32(min(max(elapsed.Milliseconds(), 1), int64(1<<32-1)))
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

// snmpWalkAll runs the GETNEXT (SNMPv1) or GETBULK loop in the agent and
// collects every varbind under rootOid. Unlike gosnmp's walk functions, any
// response error status other than NoError fails the walk — keeping the
// varbinds collected so far — so a device answering genErr, tooBig,
// authorizationError or resourceUnavailable never reports a root complete
// whose rows the server would then reconcile away. The one exception is
// SNMPv1 noSuchName: for a v1 GETNEXT walk it is how a device reports the
// normal end of the MIB. The loop also ends cleanly when a varbind carries
// EndOfMibView, NoSuchObject or NoSuchInstance, when one escapes the
// subtree, or — for a root that names a leaf — after one exact GET of the
// root, mirroring gosnmp's walk semantics.
func snmpWalkAll(ctx context.Context, conn snmpQuerier, rootOid string, v1 bool) ([]gosnmp.SnmpPDU, error) {
	if rootOid == "" || rootOid == "." {
		// gosnmp's convention: an empty root walks the internet subtree.
		rootOid = ".1.3.6.1"
	}
	root := "." + strings.TrimPrefix(rootOid, ".")

	var results []gosnmp.SnmpPDU
	oid := root
	// last is the OID every subsequent answer must exceed; a device that
	// repeats or goes backwards would loop forever otherwise.
	last := root
	exactGet := false
requestLoop:
	for {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		var packet *gosnmp.SnmpPacket
		var err error
		if exactGet {
			packet, err = conn.Get([]string{oid})
		} else if v1 {
			packet, err = conn.GetNext([]string{oid})
		} else {
			packet, err = conn.GetBulk([]string{oid}, 0, snmpMaxRepetitions)
		}
		if err != nil {
			return results, err
		}
		// Only the first GETNEXT/GETBULK of the root can reveal a leaf root.
		// It answers beyond the root, or with end-of-view (v1: noSuchName)
		// when the leaf is the last object in the device's MIB view. Either
		// way fall back to one exact GET (gosnmp issues #78, #93).
		firstRequest := !exactGet && oid == root

		switch packet.Error {
		case gosnmp.NoError:
		case gosnmp.NoSuchName:
			if v1 {
				// Normal end of the MIB for a v1 GETNEXT walk: never
				// consume the echoed varbinds of an error response.
				if firstRequest {
					exactGet = true
					continue requestLoop
				}
				return results, nil
			}
			return results, fmt.Errorf("device answered %v (error index %d) for %s", packet.Error, packet.ErrorIndex, canonicalOID(oid))
		default:
			return results, fmt.Errorf("device answered %v (error index %d) for %s", packet.Error, packet.ErrorIndex, canonicalOID(oid))
		}
		if len(packet.Variables) == 0 {
			return results, fmt.Errorf("device answered with an empty varbind list for %s", canonicalOID(oid))
		}

		for i, pdu := range packet.Variables {
			switch pdu.Type {
			case gosnmp.EndOfMibView, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
				if firstRequest && i == 0 {
					exactGet = true
					continue requestLoop
				}
				// The subtree is exhausted (or the root itself is absent):
				// a clean end, not a failure.
				return results, nil
			}
			if !strings.HasPrefix(pdu.Name, root+".") {
				if pdu.Name == root && pdu.Type != gosnmp.NoSuchInstance {
					// The requested root itself was answered: a leaf walk.
					results = append(results, pdu)
				}
				if firstRequest && i == 0 {
					// The first answer escaped the subtree: the root names a
					// leaf GETNEXT/GETBULK cannot discover.
					exactGet = true
					continue requestLoop
				}
				return results, nil
			}
			if !snmpOIDLess(last, pdu.Name) {
				return results, fmt.Errorf("device answered a non-increasing OID %s after %s", canonicalOID(pdu.Name), canonicalOID(last))
			}
			results = append(results, pdu)
			last = pdu.Name
		}
		oid = packet.Variables[len(packet.Variables)-1].Name
	}
}

// snmpOIDLess reports whether dotted OID a sorts strictly before b, comparing
// arcs numerically. It guards the walk loop against devices that repeat or
// wind back OIDs, which would otherwise never terminate.
func snmpOIDLess(a, b string) bool {
	as := strings.Split(strings.TrimPrefix(a, "."), ".")
	bs := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := range min(len(as), len(bs)) {
		an, aerr := strconv.ParseUint(as[i], 10, 64)
		bn, berr := strconv.ParseUint(bs[i], 10, 64)
		if aerr != nil || berr != nil {
			return as[i] < bs[i]
		}
		if an != bn {
			return an < bn
		}
	}
	return len(as) < len(bs)
}

// isSnmpV1 reports whether a device speaks SNMPv1, which has no GETBULK.
func isSnmpV1(version string) bool { return version == "1" || version == "v1" }

// snmpGetInto records one GET batch and returns the number of OIDs the
// device answered as absent (Null/NoSuchObject/NoSuchInstance, or v1
// noSuchName). A valid one-based v1 error index identifies only the absent
// instance: remove it from a private retry slice and request the remainder.
// Never consume the echoed varbinds of an error-status response as values.
// TooBig and unusable noSuchName indexes fall back to bounded bisection.
//
// Absent answers are recorded as empty values so the server can tell
// "collected, empty" from "never collected". The wire cannot distinguish
// "object absent" from "OID outside the credential's view" — both read as
// noSuchObject/noSuchInstance (v1: noSuchName) — so the caller must surface
// the absent count: a scoped credential otherwise prunes rows silently.
func snmpGetInto(conn snmpQuerier, dev *pb.SnmpDevice, oids []string, into map[string]string) (absent int, err error) {
	// Copy only when an indexed removal first needs to modify this batch.
	// Subsequent removals reuse that buffer; every retry strictly shrinks.
	owned := false
	for len(oids) > 0 {
		started := time.Now()
		result, getErr := conn.Get(oids)
		if getErr != nil {
			return absent, snmpGetError(oids, time.Since(started), getErr)
		}

		switch result.Error {
		case gosnmp.NoError:
			for _, v := range result.Variables {
				if !snmpValueUsable(v) {
					// The device answered: record empty, not missing.
					into[canonicalOID(v.Name)] = ""
					absent++
					continue
				}
				into[canonicalOID(v.Name)] = snmpValueToString(v)
			}
			if len(result.Variables) < len(oids) {
				absent += recordOmittedOIDs(result.Variables, oids, into)
			}
			return absent, nil
		case gosnmp.NoSuchName, gosnmp.TooBig:
			if result.Error == gosnmp.NoSuchName && isSnmpV1(dev.Version) &&
				result.ErrorIndex > 0 && int(result.ErrorIndex) <= len(oids) {
				index := int(result.ErrorIndex) - 1
				into[canonicalOID(oids[index])] = ""
				absent++
				slog.Debug("snmp get oid skipped", "device", dev.Ip, "oid", oids[index], "status", result.Error, "error_index", result.ErrorIndex)
				if len(oids) == 1 {
					return absent, nil
				}
				if !owned {
					oids = slices.Clone(oids)
					owned = true
				}
				oids = slices.Delete(oids, index, index+1)
				continue
			}
			if len(oids) == 1 {
				if result.Error == gosnmp.TooBig {
					return absent, snmpGetError(oids, time.Since(started), fmt.Errorf("status %s", result.Error))
				}
				// A singleton noSuchName still identifies the absent OID.
				into[canonicalOID(oids[0])] = ""
				absent++
				slog.Debug("snmp get oid skipped", "device", dev.Ip, "oid", oids[0], "status", result.Error, "error_index", result.ErrorIndex)
				return absent, nil
			}
			slog.Warn("snmp get batch split", "device", dev.Ip, "batch_size", len(oids), "status", result.Error, "error_index", result.ErrorIndex)
			mid := len(oids) / 2
			loAbsent, loErr := snmpGetInto(conn, dev, oids[:mid], into)
			hiAbsent, hiErr := snmpGetInto(conn, dev, oids[mid:], into)
			return absent + loAbsent + hiAbsent, errors.Join(loErr, hiErr)
		default:
			return absent, snmpGetError(oids, time.Since(started), fmt.Errorf("status %s at index %d", result.Error, result.ErrorIndex))
		}
	}
	return absent, nil
}

// recordOmittedOIDs records as absent every requested OID a NoError reply
// left out of its varbind list, and returns how many it recorded. The
// device answered the request, so the OID reads "collected, empty".
func recordOmittedOIDs(answered []gosnmp.SnmpPDU, requested []string, into map[string]string) int {
	names := make(map[string]struct{}, len(answered))
	for _, v := range answered {
		names[canonicalOID(v.Name)] = struct{}{}
	}
	omitted := 0
	for _, oid := range requested {
		key := canonicalOID(oid)
		if _, ok := names[key]; ok {
			continue
		}
		names[key] = struct{}{}
		into[key] = ""
		omitted++
	}
	return omitted
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

// executeCredentialTest tests SNMP credentials by reading the system group.
func executeCredentialTest(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	result := &pb.CredentialTestResult{TestId: job.JobId}
	if job.SnmpDevice == nil {
		slog.Error("job missing snmp device", "job_id", job.JobId)
		result.ErrorMessage = "missing device configuration"
	} else if values, err := readSystemGroup(ctx, job, "SNMP test failed"); err != nil {
		result.ErrorMessage = err.Error()
	} else {
		// A successful GET proves the credentials work even when the system
		// values are unavailable.
		result.Success = true
		result.SystemDescription = truncateBytes(values[oidSysDescr], probeMaxDescrBytes)
		result.SysObjectId = truncateBytes(values[oidSysObjectID], probeMaxOIDBytes)
		result.SysName = truncateBytes(values[oidSysName], probeMaxNameBytes)
	}
	result.Timestamp = time.Now().Unix()
	slog.Info("credential test complete", "test_id", result.TestId, "success", result.Success)
	sendResult(ctx, out, "credential_test_result", result, job.JobId)
}

// probeCandidate performs one probe attempt: dial the candidate and prove
// the credential within the attempt timeout. The timeout bounds the whole
// exchange, including gosnmp's own retries.
func probeCandidate(ctx context.Context, dev *pb.SnmpDevice, timeout time.Duration) (map[string]string, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return readSystemGroup(attemptCtx, &pb.AgentJob{SnmpDevice: dev}, "SNMP probe failed")
}

// readSystemGroup dials the job's device and proves the credential with a
// sysDescr.0 GET. failure prefixes the error of a proof GET that fails or
// answers an error status; a dial error reads "connection failed".
//
// The proof GET asks for sysDescr.0 alone: under SNMPv1 a single missing
// object fails the whole PDU with noSuchName, so bundling the identity
// OIDs into the proof would report a working credential as failed. The
// sysObjectID/sysName GET is a second, best-effort exchange: its failure
// yields empty identity values, not a rejected credential. snmpGetInto
// recovers supported instances from noSuchName responses, so a device
// missing sysName still yields its sysObjectID.
func readSystemGroup(ctx context.Context, job *pb.AgentJob, failure string) (map[string]string, error) {
	conn, closeFn, err := snmpDial(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer closeOnCancellation(ctx, closeFn)()

	packet, err := conn.Get([]string{oidSysDescr})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", failure, err)
	}
	if packet.Error != gosnmp.NoError {
		return nil, fmt.Errorf("%s: status %v (error index %d)", failure, packet.Error, packet.ErrorIndex)
	}

	values := systemValues(packet)
	_, _ = snmpGetInto(conn, job.SnmpDevice, []string{oidSysObjectID, oidSysName}, values)
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
			if !first {
				// jitterDispatch returns early on cancellation.
				jitterDispatch(ctx, delay)
				if ctx.Err() != nil {
					return
				}
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
				result.SysObjectId = truncateBytes(values[oidSysObjectID], probeMaxOIDBytes)
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
		MaxRepetitions: snmpMaxRepetitions,
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
		case "noAuthNoPriv", "":
			// The server sends "" for a credential with no stored level.
			conn.MsgFlags = gosnmp.NoAuthNoPriv
		default:
			// A misspelled level must not fall through to unauthenticated
			// requests for a credential meant to authenticate.
			return nil, fmt.Errorf("unsupported SNMPv3 security level %q", dev.V3SecurityLevel)
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
			// gosnmp decodes OID values with a leading dot; every other OID
			// the agent reports (keys, probe sysObjectID) carries none.
			return canonicalOID(value)
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
