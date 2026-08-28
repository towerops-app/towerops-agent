// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
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
	// truncates — and therefore silently discards — larger traps.
	trapReadBuffer = 65535
)

// trapListener receives SNMP traps on a UDP port and converts them to protobuf.
//
// The listener outlives any single WebSocket session: devices send traps
// whenever they like, and dropping them because the agent happens to be
// reconnecting would lose exactly the events that matter during an outage.
type trapListener struct {
	mu        sync.Mutex
	closeOnce sync.Once
	listener  *gosnmp.TrapListener
	ready     <-chan struct{}
	done      chan struct{}
	traps     chan *pb.SnmpTrap
	community string
	dropped   atomic.Uint64
	closed    chan struct{}
	port      uint16
}

// startTrapListener binds the trap port and serves until Close is called.
// A non-empty community rejects traps sent with any other community string;
// gosnmp itself performs no community validation on receive.
func startTrapListener(port uint16, community string) (*trapListener, error) {
	t := &trapListener{
		traps:     make(chan *pb.SnmpTrap, trapQueueSize),
		community: community,
		closed:    make(chan struct{}),
		port:      port,
	}

	t.listener = t.newListener()
	t.done = make(chan struct{})
	t.ready = trapReady(t.listener, t.done)

	// 0.0.0.0 rather than :port — the bare form binds dual-stack, which makes
	// the bound family depend on the host's IPv6 configuration.
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))

	errCh := make(chan error, 1)
	go t.serve(t.listener, t.done, addr, errCh)

	select {
	case <-t.ready:
		slog.Info("snmp trap listener started", "port", port, "community_filter", community != "")
		return t, nil
	case err := <-errCh:
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
		Timeout:   5 * time.Second,
		Retries:   1,
		MaxOids:   gosnmp.MaxOids,
	}
	return listener
}

func (t *trapListener) serve(listener *gosnmp.TrapListener, done chan struct{}, addr string, startupErr chan<- error) {
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
		go func(currentReady <-chan struct{}) {
			select {
			case <-currentReady:
				slog.Info("snmp trap listener rebound", "port", t.port)
			case <-t.closed:
			}
		}(ready)
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
	if t.community != "" && packet.Community != t.community {
		slog.Debug("dropping trap with unexpected community", "source", addr.IP.String())
		return
	}

	trap := trapToProto(packet, addr)
	select {
	case t.traps <- trap:
		slog.Debug("received snmp trap", "source", trap.SourceIp, "trap_oid", trap.TrapOid, "varbinds", len(trap.Varbinds))
	default:
		t.dropped.Add(1)
	}
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
		trap.GenericTrap = uint32(packet.GenericTrap)   //nolint:gosec // 0-6 per RFC 1157
		trap.SpecificTrap = uint32(packet.SpecificTrap) //nolint:gosec // device-supplied trap number
		trap.UptimeTicks = uint64(packet.Timestamp)
		trap.TrapOid = v1TrapOID(trap.Enterprise, packet.GenericTrap, packet.SpecificTrap)
	}

	for _, pdu := range packet.Variables {
		switch pdu.Name {
		case oidSysUpTime:
			// v1 carries uptime in the PDU header instead, and that value wins.
			if trap.UptimeTicks == 0 {
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
			slog.Warn("truncating trap varbinds", "source", trap.SourceIp, "limit", maxTrapVarbinds)
			break
		}
		trap.Varbinds[trimOID(pdu.Name)] = snmpValueToString(pdu)
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
// match the dotted form used everywhere else in the protocol.
func trimOID(oid string) string {
	if len(oid) > 0 && oid[0] == '.' {
		return oid[1:]
	}
	return oid
}
