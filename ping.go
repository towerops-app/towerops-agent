// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpConn is the subset of *icmp.PacketConn the shared ICMP sockets use.
// Keeping the listen hook interface-typed lets tests substitute a connection
// that returns specific read results, which a concrete *icmp.PacketConn
// cannot.
type icmpConn interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	LocalAddr() net.Addr
	Close() error
}

var icmpListenPacket = func(network, address string) (icmpConn, error) {
	return icmp.ListenPacket(network, address)
}

var icmpMarshal = func(m *icmp.Message) ([]byte, error) { return m.Marshal(nil) }

// pingSeq prevents concurrent workers from accepting one another's replies.
var pingSeq atomic.Uint32

var errPingSequenceInUse = errors.New("icmp sequence is already in use")

// pingGOOS keeps platform-specific ping arguments testable on any host.
var pingGOOS = runtime.GOOS

// pingLookPath resolves the fallback ping binaries; a seam so the IPv6 command
// choice is testable on hosts that do or do not ship ping6.
var pingLookPath = exec.LookPath

// pingCommandOutput runs the final ping(8) fallback. Tests replace it so
// command success and failure do not depend on the host network.
var pingCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// icmpPing sends a single ICMP echo request and returns the round-trip time in milliseconds.
// Tries raw ICMP sockets first (requires CAP_NET_RAW or root), then falls back to
// unprivileged UDP-based ICMP (requires ping_group_range sysctl).
func icmpPing(ctx context.Context, ip string, timeoutMs int) (float64, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv4 := parsedIP.To4() != nil

	// Try raw ICMP first (works with CAP_NET_RAW or as root)
	var rawNet string
	if isIPv4 {
		rawNet = "ip4:icmp"
	} else {
		rawNet = "ip6:ipv6-icmp"
	}
	ms, err := doICMPPing(ctx, parsedIP, rawNet, isIPv4, timeoutMs)
	if err == nil {
		return ms, nil
	}
	var unavailable *errICMPUnavailable
	if !errors.As(err, &unavailable) {
		return 0, err
	}

	// Fall back to unprivileged UDP ICMP (works with ping_group_range sysctl)
	var udpNet string
	if isIPv4 {
		udpNet = "udp4"
	} else {
		udpNet = "udp6"
	}
	return doICMPPing(ctx, parsedIP, udpNet, isIPv4, timeoutMs)
}

// pingKey routes an incoming ICMP message to the ping that is waiting for it.
// The kernel rewrites the echo identifier on unprivileged "udp" sockets to the
// local port, so replyID carries the identifier replies actually carry; an id
// of -1 marks the identifier unknown and such waiters match on seq alone.
type pingKey struct {
	id  int
	seq int
}

// icmpReply reports the terminal result of a ping to its waiter: err == nil
// means a matching echo reply arrived; otherwise the ping failed early
// (unreachable, time exceeded) or the shared socket itself died.
type icmpReply struct {
	err error
}

// pingWaiter is a single in-flight ping registered on a shared socket.
type pingWaiter struct {
	dst net.IP
	ch  chan icmpReply
}

// icmpSocket is one process-wide ICMP socket per network type. Its readLoop
// parses every inbound message once and routes it to the waiter registered
// for its (id, seq), so concurrent pings no longer each receive a copy of
// every packet. Per-ping timeouts live on the waiter side.
type icmpSocket struct {
	conn    icmpConn
	proto   int // iana protocol number: 1 or 58
	replyID int // identifier carried by echo replies; -1 when it cannot be derived
	mu      sync.Mutex
	waiters map[pingKey]*pingWaiter
	err     error // terminal read error; set once, under mu
}

var sharedSockets = struct {
	mu sync.Mutex
	m  map[string]*icmpSocket
}{m: make(map[string]*icmpSocket)}

// sharedSocket returns the long-lived socket for network, opening it on first
// use and replacing it if its read loop died.
func sharedSocket(network string) (*icmpSocket, error) {
	sharedSockets.mu.Lock()
	defer sharedSockets.mu.Unlock()
	if s := sharedSockets.m[network]; s != nil {
		if s.readErr() == nil {
			return s, nil
		}
		delete(sharedSockets.m, network)
	}

	conn, err := icmpListenPacket(network, "")
	if err != nil {
		return nil, &errICMPUnavailable{err: fmt.Errorf("icmp listen %s: %w", network, err)}
	}

	proto := 1
	if strings.HasPrefix(network, "ip6") || strings.HasPrefix(network, "udp6") {
		proto = 58
	}
	// Unprivileged UDP sockets have their echo identifier rewritten to the
	// local port, so replies come back with that identifier rather than the
	// process id.
	replyID := -1
	if strings.HasPrefix(network, "udp") {
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			replyID = localAddr.Port
		}
	} else {
		replyID = os.Getpid() & 0xffff
	}

	s := &icmpSocket{conn: conn, proto: proto, replyID: replyID, waiters: make(map[pingKey]*pingWaiter)}
	sharedSockets.m[network] = s
	go s.readLoop()
	return s, nil
}

// closeSharedSockets closes every shared socket and forgets them. Production
// sockets live for the process; tests call this to reset state.
func closeSharedSockets() {
	sharedSockets.mu.Lock()
	socks := make([]*icmpSocket, 0, len(sharedSockets.m))
	for network, s := range sharedSockets.m {
		socks = append(socks, s)
		delete(sharedSockets.m, network)
	}
	sharedSockets.mu.Unlock()
	for _, s := range socks {
		_ = s.conn.Close()
	}
}

func (s *icmpSocket) readErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// register installs a waiter under key, or returns nil if key is in use.
// A socket can die before registration; the subsequent write fails and
// doICMPPing retries once on a fresh socket.
func (s *icmpSocket) register(key pingKey, dst net.IP) *pingWaiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[key] != nil {
		return nil
	}
	w := &pingWaiter{dst: dst, ch: make(chan icmpReply, 1)}
	s.waiters[key] = w
	return w
}

func (s *icmpSocket) unregister(key pingKey, w *pingWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[key] == w {
		delete(s.waiters, key)
	}
}

// waiterFor finds the waiter a reply with the given identifier and sequence
// belongs to. Waiters registered without a known identifier (id -1) match on
// sequence alone.
func (s *icmpSocket) waiterFor(id, seq int) *pingWaiter {
	if w, ok := s.waiters[pingKey{id: id, seq: seq}]; ok {
		return w
	}
	return s.waiters[pingKey{id: -1, seq: seq}]
}

// icmpReadBackoffMax caps the pause between consecutive transient read errors
// so a socket stuck returning errors cannot spin the read loop.
var icmpReadBackoffMax = 100 * time.Millisecond

func (s *icmpSocket) readLoop() {
	rb := make([]byte, 1500)
	transient := 0
	for {
		n, peer, err := s.conn.ReadFrom(rb)
		if err != nil {
			if !isTransientICMPReadError(err) {
				s.fail(fmt.Errorf("icmp read: %w", err))
				return
			}
			// One bad read must not fail every in-flight ping: skip it, and
			// back off only when errors keep coming back to back.
			if transient > 0 {
				time.Sleep(min(time.Duration(transient)*time.Millisecond, icmpReadBackoffMax))
			}
			transient++
			continue
		}
		transient = 0
		rm, err := icmp.ParseMessage(s.proto, rb[:n])
		if err != nil {
			continue
		}
		s.dispatch(rm, peerIP(peer))
	}
}

// isTransientICMPReadError reports whether a ReadFrom error leaves the socket
// usable. On raw ICMP sockets the kernel reports a pending ICMP hard error
// (sk_err) once on the next recvfrom - ECONNREFUSED, EHOSTUNREACH and the like
// - which says nothing about the socket itself. A closed socket and anything
// unrecognised are fatal, so sharedSocket opens a fresh one.
func isTransientICMPReadError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.EHOSTDOWN, syscall.ENETDOWN, syscall.EAGAIN, syscall.EINTR,
		syscall.ENOBUFS, syscall.EMSGSIZE,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// dispatch routes one parsed ICMP message to its waiter. Echo replies match
// on (id, seq) and are additionally checked against the pinged address so a
// stray reply from another host can never satisfy a ping. Unreachable,
// time-exceeded and packet-too-big errors quote the original datagram; the
// quoted echo (id, seq) identifies the waiter and the quoted destination must
// be the pinged address - the shared raw socket sees every ICMP error on the
// host, so another process's request or a stale error after sequence wrap
// must not fail an unrelated ping. A matching error fails the waiter
// immediately instead of letting it sit out its full timeout.
func (s *icmpSocket) dispatch(rm *icmp.Message, src net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			return
		}
		w := s.waiterFor(echo.ID, echo.Seq)
		if w == nil || src == nil || !src.Equal(w.dst) {
			return
		}
		select {
		case w.ch <- icmpReply{}:
		default:
		}
	case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable,
		ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded,
		ipv6.ICMPTypePacketTooBig:
		var quoted []byte
		switch body := rm.Body.(type) {
		case *icmp.DstUnreach:
			quoted = body.Data
		case *icmp.TimeExceeded:
			quoted = body.Data
		case *icmp.PacketTooBig:
			quoted = body.Data
		}
		id, seq, dst, ok := quotedEchoIDSeq(quoted, s.proto == 1)
		if !ok {
			return
		}
		w := s.waiterFor(id, seq)
		if w == nil || !dst.Equal(w.dst) {
			return
		}
		var what string
		switch rm.Type {
		case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
			what = fmt.Sprintf("destination unreachable (code %d)", rm.Code)
		case ipv6.ICMPTypePacketTooBig:
			what = "packet too big"
		default:
			what = "time exceeded"
		}
		select {
		case w.ch <- icmpReply{err: fmt.Errorf("icmp %s for %s", what, w.dst)}:
		default:
		}
	}
}

// fail terminates the socket after a read error: all current waiters get the
// error and the connection is closed so sharedSocket opens a fresh one next
// time.
func (s *icmpSocket) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	s.err = err
	for key, w := range s.waiters {
		select {
		case w.ch <- icmpReply{err: err}:
		default:
		}
		delete(s.waiters, key)
	}
	_ = s.conn.Close()
}

// quotedEchoIDSeq extracts the echo identifier, sequence and destination of
// the original datagram quoted inside an ICMP error body. The quote is the
// original IP header followed by the first 8 bytes of the ICMP echo request,
// which is enough to route the error to the ping that sent it. dst aliases
// data.
func quotedEchoIDSeq(data []byte, isIPv4 bool) (id, seq int, dst net.IP, ok bool) {
	var icmpData []byte
	var echoType byte
	if isIPv4 {
		echoType = byte(ipv4.ICMPTypeEcho)
		if len(data) < 20 || data[0]>>4 != 4 || data[9] != 1 {
			return 0, 0, nil, false
		}
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 || len(data) < ihl+8 {
			return 0, 0, nil, false
		}
		dst = net.IP(data[16:20])
		icmpData = data[ihl:]
	} else {
		echoType = byte(ipv6.ICMPTypeEchoRequest)
		if len(data) < 48 || data[0]>>4 != 6 || data[6] != 58 {
			return 0, 0, nil, false
		}
		dst = net.IP(data[24:40])
		icmpData = data[40:]
	}
	if icmpData[0] != echoType {
		return 0, 0, nil, false
	}
	return int(binary.BigEndian.Uint16(icmpData[4:6])), int(binary.BigEndian.Uint16(icmpData[6:8])), dst, true
}

// doICMPPing performs an ICMP ping over the given network type.
// It sends one echo request on the shared socket for the network and waits on
// a keyed waiter; the matching reply, an ICMP error quoting the request, the
// context, or the timeout ends the wait.
func doICMPPing(ctx context.Context, ip net.IP, network string, isIPv4 bool, timeoutMs int) (float64, error) {
	var msgType icmp.Type
	if isIPv4 {
		msgType = ipv4.ICMPTypeEcho
	} else {
		msgType = ipv6.ICMPTypeEchoRequest
	}

	// Destination address type depends on network
	var dst net.Addr
	if strings.HasPrefix(network, "udp") {
		dst = &net.UDPAddr{IP: ip}
	} else {
		dst = &net.IPAddr{IP: ip}
	}

	var waiter sentEcho
	var start time.Time
	var err error
	// The 16-bit sequence counter can wrap while a slow ping is still
	// pending. Try another sequence instead of replacing that ping's waiter.
	for range 1 << 16 {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("icmp ping: %w", ctx.Err())
		}
		seq := int(pingSeq.Add(1) & 0xffff)
		msg := icmp.Message{
			Type: msgType,
			Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("towerops")},
		}
		wb, marshalErr := icmpMarshal(&msg)
		if marshalErr != nil {
			return 0, fmt.Errorf("icmp marshal: %w", marshalErr)
		}
		waiter, start, err = sendEcho(network, seq, ip, wb, dst)
		if !errors.Is(err, errPingSequenceInUse) {
			break
		}
	}
	if err != nil {
		return 0, err
	}
	defer waiter.sock.unregister(waiter.key, waiter.w)

	timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
	defer timer.Stop()

	select {
	case reply := <-waiter.w.ch:
		if reply.err != nil {
			return 0, reply.err
		}
		return float64(time.Since(start).Microseconds()) / 1000.0, nil
	case <-timer.C:
		return 0, fmt.Errorf("icmp reply timeout after %d ms", timeoutMs)
	case <-ctx.Done():
		return 0, fmt.Errorf("icmp ping: %w", ctx.Err())
	}
}

// sentEcho is a written echo request's registration on the socket it went out
// on; the caller unregisters it when the ping ends.
type sentEcho struct {
	sock *icmpSocket
	key  pingKey
	w    *pingWaiter
}

// sendEcho registers a waiter on the shared socket for network and writes the
// echo request. The socket can be closed between sharedSocket returning it
// and the write - its read loop failed, or it was torn down - so a
// closed-connection write marks that socket dead and is retried once on a
// fresh one rather than reporting a healthy device down.
func sendEcho(network string, seq int, ip net.IP, wb []byte, dst net.Addr) (sentEcho, time.Time, error) {
	for attempt := 0; ; attempt++ {
		sock, err := sharedSocket(network)
		if err != nil {
			return sentEcho{}, time.Time{}, err
		}
		key := pingKey{id: sock.replyID, seq: seq}
		w := sock.register(key, ip)
		if w == nil {
			return sentEcho{}, time.Time{}, errPingSequenceInUse
		}
		start := time.Now()
		_, err = sock.conn.WriteTo(wb, dst)
		if err == nil {
			return sentEcho{sock: sock, key: key, w: w}, start, nil
		}
		sock.unregister(key, w)
		if attempt == 0 && errors.Is(err, net.ErrClosed) {
			sock.fail(fmt.Errorf("icmp write: %w", err))
			continue
		}
		return sentEcho{}, time.Time{}, fmt.Errorf("icmp write: %w", err)
	}
}

func peerIP(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.IPAddr:
		if addr != nil {
			return addr.IP
		}
	case *net.UDPAddr:
		if addr != nil {
			return addr.IP
		}
	}
	return nil
}

// errICMPUnavailable is returned when the ICMP socket can't be opened.
// This triggers a fallback to exec-based ping.
type errICMPUnavailable struct{ err error }

func (e *errICMPUnavailable) Error() string { return e.err.Error() }

func (e *errICMPUnavailable) Unwrap() error { return e.err }

// pingDevice pings an IP address and returns the response time in milliseconds.
// Tries raw ICMP first for efficiency, falls back to exec-based ping only
// if the system doesn't support unprivileged ICMP.
func pingDevice(ctx context.Context, ip string, timeoutMs int) (float64, error) {
	ms, err := icmpPing(ctx, ip, timeoutMs)
	if err == nil {
		return ms, nil
	}

	// Only fall back to exec if ICMP sockets aren't available
	var unavailable *errICMPUnavailable
	if errors.As(err, &unavailable) {
		return execPing(ctx, ip, timeoutMs)
	}
	return 0, err
}

// execPing uses the system ping command as a fallback.
func execPing(parent context.Context, ip string, timeoutMs int) (float64, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	pingCmd := "ping"
	if parsedIP.To4() == nil {
		pingCmd = ipv6PingCommand()
	}

	timeoutArg := pingTimeoutArg(timeoutMs)

	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutMs+1000)*time.Millisecond)
	defer cancel()

	output, err := pingCommandOutput(ctx, pingCmd, "-c", "1", "-W", strconv.Itoa(timeoutArg), ip)
	if err != nil {
		return 0, fmt.Errorf("ping failed: %s: %w", strings.TrimSpace(string(output)), errors.Join(err, ctx.Err()))
	}

	return parsePingTime(string(output))
}

// ipv6PingCommand prefers ping6 where it exists (macOS ships it separately)
// and otherwise uses ping, whose iputils build - the one in the agent image -
// handles IPv6 addresses itself and is the only capable binary present.
func ipv6PingCommand() string {
	if _, err := pingLookPath("ping6"); err == nil {
		return "ping6"
	}
	return "ping"
}

func pingTimeoutArg(timeoutMs int) int {
	if pingGOOS == "darwin" {
		return max(1, timeoutMs)
	}
	// Whole-second ping implementations must wait through the fractional
	// second rather than declaring a device down before its timeout expires.
	return (max(1, timeoutMs)-1)/1000 + 1
}

// parsePingTime extracts the response time in milliseconds from ping output.
// BusyBox and some other ping builds print "time<1 ms" for sub-millisecond
// replies instead of a "time=" field; that still means the device answered,
// so it parses as 0 ms rather than as a failure.
func parsePingTime(output string) (float64, error) {
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "time=")
		if idx >= 0 {
			timeStr := line[idx+5:]
			end := strings.Index(timeStr, " ms")
			if end < 0 {
				end = strings.IndexByte(timeStr, ' ')
			}
			if end < 0 {
				end = len(timeStr)
			}
			return strconv.ParseFloat(timeStr[:end], 64)
		}
		// BusyBox-style "time<1 ms" or "time<1ms": the bound is below the
		// timer's millisecond resolution; report 0 ms.
		if idx := strings.Index(line, "time<"); idx >= 0 {
			boundStr := line[idx+5:]
			end := strings.IndexFunc(boundStr, func(r rune) bool {
				return r != '.' && (r < '0' || r > '9')
			})
			if end < 0 {
				end = len(boundStr)
			}
			if _, err := strconv.ParseFloat(boundStr[:end], 64); err != nil {
				return 0, fmt.Errorf("unparseable ping time bound %q: %w", boundStr[:end], err)
			}
			return 0, nil
		}
	}
	return 0, fmt.Errorf("no time= field in ping output")
}
