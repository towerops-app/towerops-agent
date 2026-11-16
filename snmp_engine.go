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
	oidSNMPsysUpTime          = "1.3.6.1.2.1.1.3.0"
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

	mu                sync.Mutex
	silent            bool
	rtt               time.Duration
	getBatchSize      int
	bulkMaxRepetition uint32

	sessionMu sync.Mutex
	session   *snmpCachedSession
}

func newSNMPDeviceState(rate float64) *snmpDeviceState {
	return &snmpDeviceState{
		limiter:           newTokenBucket(rate, nil),
		getBatchSize:      snmpMaxOIDsPerGet,
		bulkMaxRepetition: snmpMaxRepetitions,
	}
}

func (s *snmpDeviceState) isSilent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.silent
}

func (s *snmpDeviceState) markSilent() {
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
}

func (s *snmpDeviceState) markHealthy() {
	s.mu.Lock()
	s.silent = false
	s.mu.Unlock()
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

func (s *snmpDeviceState) rememberGETSize(size int) {
	if size <= 0 || size > snmpMaxOIDsPerGet {
		return
	}
	s.mu.Lock()
	s.getBatchSize = size
	s.mu.Unlock()
}

func (s *snmpDeviceState) bulkRepetitions() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bulkMaxRepetition
}

func (s *snmpDeviceState) noteTooBig() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bulkMaxRepetition > 1 {
		s.bulkMaxRepetition /= 2
	}
	return s.bulkMaxRepetition
}

func (s *snmpDeviceState) noteBulkRows(rows int) {
	if rows <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if uint32(rows) > s.bulkMaxRepetition {
		s.bulkMaxRepetition = min(64, uint32(rows))
	}
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
// identifier may match; the values are hints, not authoritative health state.
func snmpPingUnreachable(job *pb.AgentJob) bool {
	if job.DeviceId != "" {
		if reachability, ok := lastDeviceReachability(job.DeviceId); ok {
			return !reachability.reachable
		}
	}
	if job.SnmpDevice != nil {
		if reachability, ok := lastIPReachability(job.SnmpDevice.Ip); ok {
			return !reachability.reachable
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
	for _, state := range e.devices {
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
