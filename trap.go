// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/towerops-app/towerops-agent/pb"
)

const (
	// OIDs hoisted out of a v2c trap's variable bindings into dedicated fields.
	oidSysUpTime     = ".1.3.6.1.2.1.1.3.0"
	oidSnmpTrapOID   = ".1.3.6.1.6.3.1.1.4.1.0"
	oidSnmpTrapsRoot = "1.3.6.1.6.3.1.1.5"

	// genericEnterpriseSpecific is generic-trap 6 in an SNMPv1 PDU: the trap is
	// identified by enterprise + specific-trap rather than by a standard type.
	genericEnterpriseSpecific = 6

	// maxTrapVarbinds bounds how much of a hostile or broken device's trap we
	// forward. Real traps carry a handful of bindings.
	maxTrapVarbinds = 128

	// trapQueueSize is how many traps we hold while no session is connected.
	// Traps are unsolicited and bursty (a switch reboot fans out dozens), so the
	// queue absorbs a burst rather than the reconnect window.
	trapQueueSize = 1000

	// trapReadBuffer is the UDP read buffer. gosnmp defaults to 4096, which
	// truncates - and therefore silently discards - larger traps.
	trapReadBuffer = 65535
)

// trapDropLogInterval bounds how often a saturated queue warns. handle runs
// inline in gosnmp's read loop, so warning on every drop during a burst would
// itself slow the reader down and make the loss worse.
var trapDropLogInterval = time.Minute

// The listener health probe. gosnmp's read loop logs and retries every read
// error and returns only after Close, so serve's rebind never runs for a
// socket that has stopped delivering datagrams. The agent sends itself a
// trap every trapProbeInterval and closes the listener after trapProbeMisses
// probes in a row fail to arrive, which hands control back to serve.
var (
	trapProbeInterval = 30 * time.Second
	trapProbeMisses   = 3
	// trapProbeNonce is the community string that marks a probe. It is random
	// per process, so a packet from anywhere else cannot pass as a probe and
	// hide itself from the server.
	trapProbeNonce = "towerops-probe-" + rand.Text()
)

// Process-wide trap listener telemetry for the heartbeat (issue 2754). The
// session does not know the listener exists, so the state lives here: one
// listener per process makes a package singleton honest.
var (
	// trapsReportingEnabled distinguishes "agent never asked to forward
	// traps" from "traps enabled, listener state follows". proto3 cannot
	// send "absent", so the server reads enabled=true as the only signal
	// that trap_listener_state means anything.
	trapsReportingEnabled atomic.Bool
	// trapListenerState is "listening", "rebinding" or "failed" (the
	// initial bind failed). atomic.Int32 so the heartbeat goroutine reads
	// it without racing the serve loop's transitions — and so a terminal
	// "failed" can never be CAS-overwritten with "rebinding" by a serve
	// loop racing the startup error path (issue 2754 flake).
	trapListenerState atomic.Int32
	// trapDroppedTotal is the cumulative queue-full drop count, summed
	// across rebinds, which is what the heartbeat reports.
	trapDroppedTotal atomic.Uint64
)

const (
	trapStateUnset int32 = iota
	trapStateListening
	trapStateRebinding
	trapStateFailed
)

func trapListenerStateString() string {
	switch trapListenerState.Load() {
	case trapStateListening:
		return "listening"
	case trapStateRebinding:
		return "rebinding"
	case trapStateFailed:
		return "failed"
	}
	return ""
}

// beginTrapRebind moves the reported listener state to "rebinding", unless
// a failed startup bind already marked the listener terminal. A serve loop
// can race startTrapListener's error path — its Listen call returned before
// the close that would have stopped it — and without the CAS its "rebinding"
// would overwrite the "failed" the heartbeat must report (issue 2754 flake).
func beginTrapRebind() {
	for {
		state := trapListenerState.Load()
		if state == trapStateFailed || trapListenerState.CompareAndSwap(state, trapStateRebinding) {
			return
		}
	}
}

// trapListener receives SNMP traps on a UDP port and converts them to protobuf.
//
// The listener outlives any single WebSocket session: devices send traps
// whenever they like, and dropping them because the agent happens to be
// reconnecting would lose exactly the events that matter during an outage.
type trapListener struct {
	mu          sync.Mutex
	closeOnce   sync.Once
	listener    *gosnmp.TrapListener
	ready       <-chan struct{}
	done        chan struct{}
	traps       chan *pb.SnmpTrap
	community   string
	bindAddr    string
	dropped     atomic.Uint64
	lastDropLog atomic.Int64
	closed      chan struct{}
	port        uint16
	// probeSeen is set by handle when a probe arrives and cleared by probe
	// on each check. probeWorks records that any probe ever arrived.
	probeSeen  atomic.Bool
	probeWorks atomic.Bool
}

// startTrapListener binds the trap port and serves until Close is called.
// A non-empty community rejects traps sent with any other community string;
// gosnmp itself performs no community validation on receive.
func startTrapListener(bindAddr string, port uint16, community string) (*trapListener, error) {
	// Normalize an empty address to 0.0.0.0 rather than using :port - the bare
	// form binds dual-stack, which makes the family depend on the host's IPv6
	// configuration.
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	t := &trapListener{
		traps:     make(chan *pb.SnmpTrap, trapQueueSize),
		community: community,
		bindAddr:  bindAddr,
		closed:    make(chan struct{}),
		port:      port,
	}

	listener := t.newListener()
	done := make(chan struct{})
	t.listener = listener
	t.done = done
	t.ready = trapReady(listener, done)

	errCh := make(chan error, 1)
	go t.serve(listener, done, errCh)

	select {
	case <-t.ready:
		trapListenerState.Store(trapStateListening)
		slog.Info("snmp trap listener started", "bind_address", bindAddr, "port", port, "community_filter", community != "")
		go t.probe(listener, done)
		return t, nil
	case err := <-errCh:
		trapListenerState.Store(trapStateFailed)
		t.Close()
		return nil, fmt.Errorf("bind trap port %d: %w", port, err)
	}
}

func (t *trapListener) newListener() *gosnmp.TrapListener {
	listener := gosnmp.NewTrapListener().WithBufferSize(trapReadBuffer)
	listener.OnNewTrap = t.handle
	listener.Params = &gosnmp.GoSNMP{
		Port:      t.port,
		Transport: "udp",
		Version:   gosnmp.Version2c,
	}
	return listener
}

func (t *trapListener) serve(listener *gosnmp.TrapListener, done chan struct{}, startupErr chan<- error) {
	addr := net.JoinHostPort(t.bindAddr, strconv.Itoa(int(t.port)))
	for {
		err := listener.Listen(addr)
		close(done)
		if startupErr != nil {
			startupErr <- err
			startupErr = nil
		}
		select {
		case <-t.closed:
			return
		default:
		}
		// A failed startup bind is terminal, not rebindable: startTrapListener
		// records "failed" and closes the listener, but this loop can race the
		// close and reach the rebind anyway. beginTrapRebind's CAS never
		// overwrites "failed" (issue 2754 flake).
		beginTrapRebind()
		slog.Error("snmp trap listener stopped unexpectedly; rebinding", "error", err, "port", t.port)

		timer := time.NewTimer(time.Second)
		select {
		case <-t.closed:
			timer.Stop()
			return
		case <-timer.C:
		}

		listener = t.newListener()
		done = make(chan struct{})
		ready := trapReady(listener, done)
		t.mu.Lock()
		select {
		case <-t.closed:
			t.mu.Unlock()
			return
		default:
			t.listener = listener
			t.ready = ready
			t.done = done
			t.mu.Unlock()
		}
		go func(currentReady <-chan struct{}, current *gosnmp.TrapListener, currentDone <-chan struct{}) {
			select {
			case <-currentReady:
				trapListenerState.Store(trapStateListening)
				slog.Info("snmp trap listener rebound", "port", t.port)
				t.probe(current, currentDone)
			case <-t.closed:
			}
		}(ready, listener, done)
	}
}

func trapReady(listener *gosnmp.TrapListener, done <-chan struct{}) <-chan struct{} {
	ready := make(chan struct{})
	go func() {
		select {
		case <-listener.Listening():
			close(ready)
		case <-done:
		}
	}()
	return ready
}

// probe sends a probe trap to listener every trapProbeInterval and closes it
// after trapProbeMisses consecutive probes fail to arrive. It returns when
// listener's serve iteration ends (done) or after it closes the listener.
//
// If no probe has ever arrived, the probe path itself is blocked (a host
// firewall dropping loopback traffic to the trap port, say). Closing would
// then restart a working listener every few intervals, so probe stops instead.
func (t *trapListener) probe(listener *gosnmp.TrapListener, done <-chan struct{}) {
	ticker := time.NewTicker(trapProbeInterval)
	defer ticker.Stop()
	t.probeSeen.Store(false)
	misses := 0
	for {
		if err := sendTrapProbe(t.bindAddr, t.port); err != nil {
			slog.Debug("snmp trap probe send failed", "error", err)
		}
		select {
		case <-ticker.C:
		case <-done:
			return
		}
		if t.probeSeen.Swap(false) {
			t.probeWorks.Store(true)
			misses = 0
			continue
		}
		misses++
		if misses < trapProbeMisses {
			continue
		}
		if !t.probeWorks.Load() {
			slog.Warn("snmp trap probe never arrived; listener health check disabled",
				"bind_address", t.bindAddr, "port", t.port)
			return
		}
		slog.Error("snmp trap listener stopped receiving its own probes; restarting",
			"port", t.port, "missed", misses)
		listener.Close()
		return
	}
}

// sendTrapProbe sends one v2c trap carrying trapProbeNonce to the listener's
// bound address. It resolves the address the way gosnmp's listener does, so a
// hostname that maps to both families probes the family that was bound.
func sendTrapProbe(bindAddr string, port uint16) error {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindAddr, strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	sender := &gosnmp.GoSNMP{
		Target:    trapProbeHost(addr.IP),
		Port:      port,
		Transport: "udp",
		Community: trapProbeNonce,
		Version:   gosnmp.Version2c,
		Timeout:   time.Second,
		MaxOids:   gosnmp.MaxOids,
	}
	if err = sender.Connect(); err == nil {
		_, err = sender.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
			// zeroDotZero: the probe identifies itself by community alone.
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: "0.0"},
		}})
		_ = sender.Conn.Close()
	}
	return err
}

// trapProbeHost maps a wildcard bind address to the loopback address of the
// same family, which the wildcard socket also receives on.
func trapProbeHost(ip net.IP) string {
	if !ip.IsUnspecified() {
		return ip.String()
	}
	if ip.To4() != nil {
		return "127.0.0.1"
	}
	return "::1"
}

// Close stops the listener. Safe to call from any goroutine.
func (t *trapListener) Close() {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.mu.Lock()
		listener := t.listener
		ready := t.ready
		done := t.done
		t.mu.Unlock()
		select {
		case <-ready:
			listener.Close()
		case <-done:
		}
	})
	if dropped := t.dropped.Load(); dropped > 0 {
		slog.Warn("snmp traps dropped while queue was full", "count", dropped)
	}
}

// Traps returns the channel traps are delivered on.
func (t *trapListener) Traps() <-chan *pb.SnmpTrap {
	return t.traps
}

// handle runs inline in gosnmp's read loop, so it only converts and enqueues:
// blocking here drops traps in the kernel buffer.
func (t *trapListener) handle(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	if packet == nil || addr == nil {
		return
	}
	if packet.Community == trapProbeNonce {
		// Our own health probe: proof the socket still delivers, never a trap.
		t.probeSeen.Store(true)
		return
	}
	if t.community != "" && packet.Community != t.community {
		slog.Debug("dropping trap with unexpected community", "source", addr.IP.String())
		return
	}
	if packet.PDUType == gosnmp.Trap && (packet.GenericTrap < 0 || packet.GenericTrap > genericEnterpriseSpecific) {
		// RFC 1157 bounds generic-trap to 0..6. Out of range it has no trap
		// OID, and a negative value would wrap to 4294967295 in the uint32
		// field, which the server rejects.
		slog.Debug("dropping v1 trap with out-of-range generic trap", "source", addr.IP.String(), "generic_trap", packet.GenericTrap)
		return
	}

	trap := trapToProto(packet, addr)
	select {
	case t.traps <- trap:
		slog.Debug("received snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid, "varbinds", len(trap.Varbinds))
	default:
		trapDroppedTotal.Add(1)
		t.reportDrop(t.dropped.Add(1))
	}
}

// reportDrop warns about a saturated queue at most once per
// trapDropLogInterval. A long-running agent whose queue keeps overflowing
// otherwise gives no signal at all until it exits.
func (t *trapListener) reportDrop(dropped uint64) {
	now := time.Now().UnixNano()
	last := t.lastDropLog.Load()
	if last != 0 && now-last < int64(trapDropLogInterval) {
		return
	}
	// Losing the race means another drop is warning right now; one line is
	// the point of the rate limit.
	if !t.lastDropLog.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("snmp trap queue full, dropping traps",
		"dropped_total", dropped, "queue_size", trapQueueSize)
}

// trapToProto converts a received trap packet to its wire representation.
// SNMPv1 header fields are mapped to a v2c-style trap OID per RFC 3584 section
// 3.1 so the server has one identifier to key on regardless of trap version.
func trapToProto(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) *pb.SnmpTrap {
	trap := &pb.SnmpTrap{
		SourceIp:  addr.IP.String(),
		Version:   trapVersion(packet.Version),
		Varbinds:  make(map[string]string, min(len(packet.Variables), maxTrapVarbinds)),
		Timestamp: time.Now().Unix(),
	}

	if packet.PDUType == gosnmp.Trap {
		trap.Enterprise = trimOID(packet.Enterprise)
		trap.GenericTrap = uint32(packet.GenericTrap)   //nolint:gosec // handle drops values outside 0-6
		trap.SpecificTrap = uint32(packet.SpecificTrap) //nolint:gosec // device-supplied trap number
		trap.UptimeTicks = uint64(packet.Timestamp)
		trap.TrapOid = v1TrapOID(trap.Enterprise, packet.GenericTrap, packet.SpecificTrap)
		trap.AgentAddress = v1AgentAddress(packet.AgentAddress)
	}

	truncated := false
	for _, pdu := range packet.Variables {
		switch pdu.Name {
		case oidSysUpTime:
			// v1 carries uptime in the PDU header instead, and that value wins.
			if packet.PDUType != gosnmp.Trap && trap.UptimeTicks == 0 {
				trap.UptimeTicks = uptimeTicks(pdu)
			}
			continue
		case oidSnmpTrapOID:
			if trap.TrapOid == "" {
				trap.TrapOid = trimOID(snmpValueToString(pdu))
			}
			continue
		}
		if len(trap.Varbinds) >= maxTrapVarbinds {
			// Keep scanning for metadata even after the forwarded map is full.
			truncated = true
			continue
		}
		trap.Varbinds[trimOID(pdu.Name)] = snmpValueToString(pdu)
	}
	if truncated {
		slog.Warn("truncating trap varbinds", "source", trap.SourceIp, "limit", maxTrapVarbinds)
	}

	return trap
}

// trapVersion maps gosnmp's wire version bytes to the protocol version numbers
// the wire contract uses (gosnmp's Version1 is 0x0, which would be ambiguous).
func trapVersion(v gosnmp.SnmpVersion) uint32 {
	switch v {
	case gosnmp.Version1:
		return 1
	case gosnmp.Version2c:
		return 2
	case gosnmp.Version3:
		return 3
	default:
		return 0
	}
}

// v1TrapOID applies the RFC 3584 section 3.1 mapping: a generic trap becomes
// snmpTraps.<generic+1>, and an enterprise-specific trap becomes
// <enterprise>.0.<specific>.
func v1TrapOID(enterprise string, generic, specific int) string {
	if generic == genericEnterpriseSpecific {
		if enterprise == "" {
			return ""
		}
		return enterprise + ".0." + strconv.Itoa(specific)
	}
	if generic < 0 || generic > 5 {
		return ""
	}
	return oidSnmpTrapsRoot + "." + strconv.Itoa(generic+1)
}

// v1AgentAddress returns a v1 PDU's agent-addr as dotted IPv4, or "" when the
// device left it unset or sent 0.0.0.0. A relay forwards traps from its own
// address, so this is the only field that names the originating device.
func v1AgentAddress(raw string) string {
	ip := net.ParseIP(raw).To4()
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// uptimeTicks reads a sysUpTime binding, which devices send as TimeTicks but
// occasionally as a plain integer type.
func uptimeTicks(pdu gosnmp.SnmpPDU) uint64 {
	switch v := pdu.Value.(type) {
	case uint32:
		return uint64(v)
	case uint:
		return uint64(v)
	case uint64:
		return v
	case int:
		if v < 0 {
			return 0
		}
		return uint64(v)
	default:
		ticks, err := strconv.ParseUint(snmpValueToString(pdu), 10, 64)
		if err != nil {
			return 0
		}
		return ticks
	}
}

// trimOID strips the leading dot gosnmp puts on decoded OIDs so stored OIDs
// match the undotted form the protocol uses for every OID map.
func trimOID(oid string) string {
	if len(oid) > 0 && oid[0] == '.' {
		return oid[1:]
	}
	return oid
}
