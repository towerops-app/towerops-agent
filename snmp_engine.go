// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
	"google.golang.org/protobuf/proto"
)

const (
	defaultSNMPRequestTimeout = 3 * time.Second
	defaultSNMPRetries        = 1
	snmpSilentProbeTimeout    = 2 * time.Second
	snmpSessionIdleTimeout    = 5 * time.Minute
	// snmpDeviceStateIdleTTL bounds how long an untouched device entry lives:
	// credential probes key state by address, so without eviction every
	// probed address accretes a permanent entry (issue 5158).
	snmpDeviceStateIdleTTL = 30 * time.Minute
	// snmpAdaptiveRecoverAfter is the count of consecutive clean exchanges
	// that steps a degraded batch size back up.
	snmpAdaptiveRecoverAfter = 4
	// snmpAdaptiveCeilingTTL keeps the last failed size a soft ceiling on
	// recovery growth; once it expires the size may climb past it.
	snmpAdaptiveCeilingTTL = 10 * time.Minute
	oidSNMPsysUpTime       = "1.3.6.1.2.1.1.3.0"

	// snmpPingHintMaxAge bounds how long a ping outcome may suppress silent
	// recovery probes: a hint from a long-abandoned or cancelled round must
	// not latch a device into "skip every tick" (issue 5156).
	snmpPingHintMaxAge = 3 * time.Minute
	// snmpSilentMaxSkips bounds consecutive hint-suppressed ticks, so a
	// device that filters ICMP still gets probed periodically.
	snmpSilentMaxSkips = 10
)

// The ping engine publishes deviceReachability (ping_engine.go); SNMP reads
// it as a hint. An unreachable hint suppresses only silent-device probes:
// ICMP filtering must not suppress ordinary SNMP polling of an otherwise
// healthy device.

// snmpCredentials is the comparable connection-affecting portion of a device
// configuration. Keeping one value per cached session makes credential and
// endpoint replacement deterministic without hashing or logging secrets.
type snmpCredentials struct {
	ip              string
	community       string
	version         string
	port            uint32
	v3SecurityLevel string
	v3Username      string
	v3AuthProtocol  string
	v3AuthPassword  string
	v3PrivProtocol  string
	v3PrivPassword  string
	transport       string
}

func snmpCredentialsFromDevice(dev *pb.SnmpDevice) snmpCredentials {
	return snmpCredentials{
		ip: dev.Ip, community: dev.Community, version: dev.Version, port: dev.Port,
		v3SecurityLevel: dev.V3SecurityLevel, v3Username: dev.V3Username,
		v3AuthProtocol: dev.V3AuthProtocol, v3AuthPassword: dev.V3AuthPassword,
		v3PrivProtocol: dev.V3PrivProtocol, v3PrivPassword: dev.V3PrivPassword,
		transport: dev.Transport,
	}
}

type snmpCachedSession struct {
	credentials snmpCredentials
	conn        *gosnmp.GoSNMP
	lastUsed    time.Time
}

// snmpDeviceState owns all state that must survive individual polls. The
// session mutex is held for a whole job because gosnmp's mutable Context,
// Timeout and Retries fields are per connection. Health and tuning have a
// separate lock so metrics and ping publication never wait on network I/O.
type snmpDeviceState struct {
	limiter *tokenBucket

	mu     sync.Mutex
	silent bool
	// pingWasUnreachable records whether the ping hint already said
	// unreachable when the device went silent: that combination means ICMP
	// filtering, not a shared outage, so the hint must not suppress probes.
	pingWasUnreachable bool
	// silentSkips counts consecutive ticks the ping hint suppressed.
	silentSkips       int
	rtt               time.Duration
	getBatchSize      int
	bulkMaxRepetition uint32
	// Adaptive sizes only shrink today; these fields drive the recovery.
	// Clean counters grow a degraded size after snmpAdaptiveRecoverAfter
	// consecutive successes, while the last size that failed stays a soft
	// ceiling until snmpAdaptiveCeilingTTL passes (issue 5158).
	getCleanBatches  int
	getFailCeiling   int
	getFailAt        time.Time
	bulkCleanReplies int
	bulkFailCeiling  uint32
	bulkFailAt       time.Time
	// lastSeen stamps the last job that used this state; idle entries are
	// evicted so probe-only addresses and removed devices do not accrete.
	lastSeen time.Time

	sessionMu sync.Mutex
	session   *snmpCachedSession
}

func newSNMPDeviceState(rate float64) *snmpDeviceState {
	return &snmpDeviceState{
		limiter:           newTokenBucket(rate, nil),
		getBatchSize:      snmpMaxOIDsPerGet,
		bulkMaxRepetition: snmpMaxRepetitions,
		lastSeen:          time.Now(),
	}
}

func (s *snmpDeviceState) isSilent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.silent
}

func (s *snmpDeviceState) markSilent(pingWasUnreachable bool) {
	s.mu.Lock()
	s.silent = true
	s.pingWasUnreachable = pingWasUnreachable
	s.silentSkips = 0
	s.mu.Unlock()
}

func (s *snmpDeviceState) markHealthy() {
	s.mu.Lock()
	s.silent = false
	s.pingWasUnreachable = false
	s.silentSkips = 0
	s.mu.Unlock()
}

// silentProbeDue decides whether a silent device gets a recovery probe on
// this tick. A fresh unreachable ping hint may suppress the probe, but never
// when the hint was already failing before the device went silent (ICMP
// filtering is unrelated to SNMP health) and never more than
// snmpSilentMaxSkips ticks in a row (issue 5156).
func (s *snmpDeviceState) silentProbeDue(job *pb.AgentJob) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pingWasUnreachable && s.silentSkips < snmpSilentMaxSkips && snmpPingUnreachable(job) {
		s.silentSkips++
		return false
	}
	s.silentSkips = 0
	return true
}

// observeRTT uses an EWMA so one delayed response does not immediately undo
// many good samples. The next timeout is four times the measured RTT, bounded
// to retain prompt failure detection and still accommodate slow links.
func (s *snmpDeviceState) observeRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	s.mu.Lock()
	if s.rtt == 0 {
		s.rtt = sample
	} else {
		s.rtt = (3*s.rtt + sample) / 4
	}
	s.mu.Unlock()
}

func (s *snmpDeviceState) requestTimeout() time.Duration {
	s.mu.Lock()
	rtt := s.rtt
	s.mu.Unlock()
	if rtt == 0 {
		return defaultSNMPRequestTimeout
	}
	return min(max(4*rtt, 250*time.Millisecond), 10*time.Second)
}

func (s *snmpDeviceState) getSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getBatchSize
}

// rememberGETSize ratchets the batch size down to a size that just worked.
// It never grows the size: recovery moves back up on clean-batch evidence,
// which is the only way a one-off loss does not pin the device small.
func (s *snmpDeviceState) rememberGETSize(size int) {
	if size <= 0 || size > snmpMaxOIDsPerGet {
		return
	}
	s.mu.Lock()
	s.getBatchSize = min(s.getBatchSize, size)
	s.mu.Unlock()
}

// noteGetFailure records the batch size that timed out or came back tooBig.
// The failed size stays a soft ceiling on recovery so growth cannot walk
// straight back into the request that failed.
func (s *snmpDeviceState) noteGetFailure(size int) {
	if size <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getCleanBatches = 0
	s.getFailCeiling = size
	s.getFailAt = time.Now()
}

// noteGetBatchOK counts one cleanly answered GET batch. After
// snmpAdaptiveRecoverAfter in a row the batch size steps halfway back toward
// the remaining headroom, staying below the failed size until it expires.
func (s *snmpDeviceState) noteGetBatchOK() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getBatchSize >= snmpMaxOIDsPerGet {
		return
	}
	s.getCleanBatches++
	if s.getCleanBatches < snmpAdaptiveRecoverAfter {
		return
	}
	s.getCleanBatches = 0
	ceiling := s.getCeilingAtLocked(time.Now())
	s.getBatchSize = min(ceiling, s.getBatchSize+max(1, (ceiling-s.getBatchSize)/2))
}

// getCeilingAtLocked is the largest batch size growth may reach: one below
// the last failed size while that failure is fresh, the default afterwards.
func (s *snmpDeviceState) getCeilingAtLocked(now time.Time) int {
	if s.getFailCeiling > 1 && now.Sub(s.getFailAt) < snmpAdaptiveCeilingTTL {
		return min(snmpMaxOIDsPerGet, s.getFailCeiling-1)
	}
	return snmpMaxOIDsPerGet
}

func (s *snmpDeviceState) bulkRepetitions() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bulkMaxRepetition
}

// noteBulkTooBig halves the remembered max-repetitions after a tooBig and
// keeps the failed request size as a soft ceiling on later recovery.
func (s *snmpDeviceState) noteBulkTooBig(requested uint32) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bulkCleanReplies = 0
	s.bulkFailCeiling = requested
	s.bulkFailAt = time.Now()
	halved := max(1, requested/2)
	s.bulkMaxRepetition = min(s.bulkMaxRepetition, halved)
	return s.bulkMaxRepetition
}

// noteBulkFull counts a GETBULK reply that filled every requested row: the
// device demonstrably takes more than it is being given. After
// snmpAdaptiveRecoverAfter in a row, max-repetitions steps halfway back to
// the ceiling so a device that degraded once does not stay small forever.
func (s *snmpDeviceState) noteBulkFull() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	const hardCeiling = 64
	s.bulkCleanReplies++
	if s.bulkCleanReplies < snmpAdaptiveRecoverAfter || s.bulkMaxRepetition >= hardCeiling {
		return s.bulkMaxRepetition
	}
	s.bulkCleanReplies = 0
	ceiling := uint32(hardCeiling)
	if s.bulkFailCeiling > 1 && time.Since(s.bulkFailAt) < snmpAdaptiveCeilingTTL {
		ceiling = min(ceiling, s.bulkFailCeiling-1)
	}
	s.bulkMaxRepetition = min(ceiling, s.bulkMaxRepetition+max(1, (ceiling-s.bulkMaxRepetition)/2))
	return s.bulkMaxRepetition
}

// snmpEngine is deliberately independent of worker pools. The scheduler owns
// admission/concurrency; this type owns per-device protocol resources.
type snmpEngine struct {
	mu         sync.Mutex
	devices    map[string]*snmpDeviceState
	deviceRate float64
}

func newSNMPEngine() *snmpEngine {
	return &snmpEngine{
		devices:    make(map[string]*snmpDeviceState),
		deviceRate: defaultSNMPDevicePDURate,
	}
}

var defaultSNMPEngine = newSNMPEngine()

func snmpStateKey(job *pb.AgentJob) string {
	if job.DeviceId != "" {
		return "id:" + job.DeviceId
	}
	dev := job.SnmpDevice
	if dev == nil {
		return "unknown"
	}
	return fmt.Sprintf("address:%s:%d:%s", dev.Ip, dev.Port, dev.Transport)
}

func (e *snmpEngine) state(job *pb.AgentJob) *snmpDeviceState {
	key := snmpStateKey(job)
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.devices[key]
	if state == nil {
		state = newSNMPDeviceState(e.deviceRate)
		e.devices[key] = state
	}
	state.touch()
	return state
}

func (e *snmpEngine) setDeviceRate(rate float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deviceRate = rate
	for _, state := range e.devices {
		state.limiter.setRate(rate)
	}
}

// snmpPingUnreachable reports the ping engine's latest outcome. Either
// identifier may match; the values are hints, not authoritative health
// state, and a hint older than snmpPingHintMaxAge stops counting so an
// abandoned round cannot suppress probes forever (issue 5156).
func snmpPingUnreachable(job *pb.AgentJob) bool {
	staleOrUnreachable := func(entry deviceReachability) bool {
		return !entry.reachable && time.Since(entry.at) < snmpPingHintMaxAge
	}
	if job.DeviceId != "" {
		if reachability, ok := lastDeviceReachability(job.DeviceId); ok {
			return staleOrUnreachable(reachability)
		}
	}
	if job.SnmpDevice != nil {
		if reachability, ok := lastIPReachability(job.SnmpDevice.Ip); ok {
			return staleOrUnreachable(reachability)
		}
	}
	return false
}

// snmpNoRetriesKey lets the silent-health probe request zero retries even
// though protobuf's zero SnmpRetries means "use the agent default".
type snmpNoRetriesKey struct{}

func snmpWithoutRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, snmpNoRetriesKey{}, true)
}

func snmpRetriesDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(snmpNoRetriesKey{}).(bool)
	return disabled
}

// dial returns the one cached connection for this device. Its close function
// releases the device session, not the socket; cancellation closes and evicts
// a socket that may have an interrupted request in flight.
func (s *snmpDeviceState) dial(ctx context.Context, job *pb.AgentJob) (snmpQuerier, func(), error) {
	s.sessionMu.Lock()
	credentials := snmpCredentialsFromDevice(job.SnmpDevice)
	now := time.Now()
	if s.session != nil && (s.session.credentials != credentials || now.Sub(s.session.lastUsed) >= snmpSessionIdleTimeout) {
		_ = s.session.conn.Conn.Close()
		s.session = nil
	}
	if s.session == nil {
		// A cached connection must not retain the first job's cancellation.
		conn, err := newSnmpConn(context.WithoutCancel(ctx), job.SnmpDevice)
		if err != nil {
			s.sessionMu.Unlock()
			return nil, nil, err
		}
		s.session = &snmpCachedSession{credentials: credentials, conn: conn}
	}

	session := s.session
	conn := session.conn
	conn.Context = ctx
	conn.Timeout = s.requestTimeout()
	conn.Retries = defaultSNMPRetries
	if job.SnmpTimeoutMs > 0 {
		conn.Timeout = time.Duration(job.SnmpTimeoutMs) * time.Millisecond
	}
	if job.SnmpRetriesSet {
		// Field 18 makes zero authoritative; the legacy retry field alone
		// keeps zero meaning "agent default".
		conn.Retries = int(job.SnmpRetries)
	} else if job.SnmpRetries > 0 {
		conn.Retries = int(job.SnmpRetries)
	}
	if snmpRetriesDisabled(ctx) {
		conn.Timeout = snmpSilentProbeTimeout
		conn.Retries = 0
	}
	conn.OnSent = snmpDeviceSentHook(s.limiter)

	querier := &rateLimitedQuerier{ctx: ctx, q: conn, device: s.limiter, cached: true}
	var once sync.Once
	release := func() {
		once.Do(func() {
			if ctx.Err() != nil {
				_ = conn.Conn.Close()
				s.session = nil
			} else if s.session != nil {
				s.session.lastUsed = time.Now()
			}
			s.sessionMu.Unlock()
		})
	}
	return querier, release, nil
}

func cachedSNMPQuerier(q snmpQuerier) bool {
	limited, ok := q.(*rateLimitedQuerier)
	return ok && limited.cached
}

// closeSNMPAfterJob retains healthy cached sessions but preserves the old
// close-on-cancel behavior for test transports and non-cache dialers.
func closeSNMPAfterJob(ctx context.Context, q snmpQuerier, closeFn func()) func() {
	if cachedSNMPQuerier(q) {
		return closeFn
	}
	return closeOnCancellation(ctx, closeFn)
}

func (s *snmpDeviceState) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// evictable reports whether the entry may leave the device map: no cached
// session is held and no job has used it within the TTL.
func (s *snmpDeviceState) evictable(now time.Time, ttl time.Duration) bool {
	if !s.sessionMu.TryLock() {
		// A running job owns the session; never stall maintenance behind it.
		return false
	}
	hasSession := s.session != nil
	s.sessionMu.Unlock()
	if hasSession {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.lastSeen) >= ttl
}

func (s *snmpDeviceState) closeIdle(now time.Time, all bool) {
	if all {
		s.sessionMu.Lock()
	} else if !s.sessionMu.TryLock() {
		// A running job owns the session; never stall maintenance behind it.
		return
	}
	defer s.sessionMu.Unlock()
	if s.session != nil && (all || now.Sub(s.session.lastUsed) >= snmpSessionIdleTimeout) {
		_ = s.session.conn.Conn.Close()
		s.session = nil
	}
}

// expireSNMPSessions is suitable for a periodic maintenance ticker. Passing
// all=true is the shutdown path and synchronously releases every UDP/TCP socket.
func (e *snmpEngine) expireSessions(now time.Time, all bool) {
	e.mu.Lock()
	states := make([]*snmpDeviceState, 0, len(e.devices))
	for key, state := range e.devices {
		if !all && state.evictable(now, snmpDeviceStateIdleTTL) {
			delete(e.devices, key)
			continue
		}
		states = append(states, state)
	}
	e.mu.Unlock()
	for _, state := range states {
		state.closeIdle(now, all)
	}
}

func expireSNMPSessions(now time.Time) { defaultSNMPEngine.expireSessions(now, false) }
func closeSNMPSessions()               { defaultSNMPEngine.expireSessions(time.Now(), true) }

// resetSNMPDeviceState removes all per-device engine state: silent health,
// RTT adaptation, batch/bulk tuning, limiter debt and the cached session.
// Tests that reuse a device ID call it in cleanup so one timeout cannot
// turn a later test into a silent-health probe.
func resetSNMPDeviceState(job *pb.AgentJob) {
	key := snmpStateKey(job)
	defaultSNMPEngine.mu.Lock()
	state := defaultSNMPEngine.devices[key]
	delete(defaultSNMPEngine.devices, key)
	defaultSNMPEngine.mu.Unlock()
	if state != nil {
		state.closeIdle(time.Now(), true)
	}
}

// snmpObservation is per-job, not per-device: B5 may shrink a batch only after
// an earlier response in the same job, while A3 marks a device silent only
// when the whole job received nothing.
type snmpObservation struct {
	responded bool
}

// observe records the delegated exchange from the rate limiter's network
// window. Waiting for a send slot is neither a response nor a timeout.
func (o *snmpObservation) observe(elapsed time.Duration, err error) {
	if err == nil {
		o.responded = true
		return
	}
	if isSNMPTimeout(err) {
		processMetrics.snmpTimeouts.Add(1)
	}
}

// snmpJobQuerier measures real exchanges outside the rate limiter so limiter
// waits never inflate RTT or request timeout adaptation.
type snmpJobQuerier struct {
	q           snmpQuerier
	state       *snmpDeviceState
	observation *snmpObservation
}

func isSNMPTimeout(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Some gosnmp transports wrap timeout text without preserving net.Error.
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "timeout") || strings.Contains(message, "timed out")
}

func (q *snmpJobQuerier) observe(started time.Time, err error) {
	elapsed := time.Since(started)
	if err == nil {
		q.observation.responded = true
		if q.state != nil {
			q.state.observeRTT(elapsed)
		}
		return
	}
	if isSNMPTimeout(err) {
		processMetrics.snmpTimeouts.Add(1)
	}
}

func (q *snmpJobQuerier) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	started := time.Now()
	packet, err := q.q.Get(oids)
	q.observe(started, err)
	return packet, err
}

func (q *snmpJobQuerier) GetNext(oids []string) (*gosnmp.SnmpPacket, error) {
	started := time.Now()
	packet, err := q.q.GetNext(oids)
	q.observe(started, err)
	return packet, err
}

func (q *snmpJobQuerier) GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (*gosnmp.SnmpPacket, error) {
	started := time.Now()
	packet, err := q.q.GetBulk(oids, nonRepeaters, maxRepetitions)
	q.observe(started, err)
	return packet, err
}

// waitForSNMPAdmission settles outstanding device/global limiter debt before
// the caller starts deadline_ms. Per-request pacing remains in the querier;
// this pre-deadline admission prevents an already saturated limiter from
// consuming the job's entire network time budget before its first request.
func waitForSNMPAdmission(ctx context.Context, job *pb.AgentJob) bool {
	if job.SnmpDevice == nil {
		return true
	}
	return waitSNMPBuckets(ctx, defaultSNMPEngine.state(job).limiter)
}

// probeSilentSNMP performs exactly one sysUpTime.0 GET with a 2s, zero-retry
// request configuration. A parsed NoError response proves reachability even
// when the device's view does not expose sysUpTime.
func probeSilentSNMP(ctx context.Context, job *pb.AgentJob, state *snmpDeviceState) error {
	probeJob := proto.Clone(job).(*pb.AgentJob)
	probeJob.SnmpTimeoutMs = uint32(snmpSilentProbeTimeout / time.Millisecond)
	probeJob.SnmpRetries = 0
	probeJob.DeadlineMs = 0
	probeCtx, cancel := context.WithTimeout(snmpWithoutRetries(ctx), snmpSilentProbeTimeout)
	defer cancel()
	conn, closeFn, err := snmpDial(probeCtx, probeJob)
	if err != nil {
		return err
	}
	defer closeSNMPAfterJob(probeCtx, conn, closeFn)()
	observation := &snmpObservation{}
	conn = &snmpJobQuerier{q: conn, state: state, observation: observation}
	packet, err := conn.Get([]string{oidSNMPsysUpTime})
	if err != nil {
		return err
	}
	if packet.Error != gosnmp.NoError {
		return fmt.Errorf("sysUpTime probe answered %v (error index %d)", packet.Error, packet.ErrorIndex)
	}
	return nil
}
