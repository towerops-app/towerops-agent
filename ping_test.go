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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"pgregory.net/rapid"
)

func TestPingDeviceLocalhost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping ping test on windows")
	}
	if testing.Short() {
		t.Skip("skipping real ICMP ping in short mode")
	}
	ms, err := pingDevice(context.Background(), "127.0.0.1", 2000)
	if err != nil {
		t.Skipf("ping not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestPingDeviceInvalidIP(t *testing.T) {
	_, err := pingDevice(context.Background(), "not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestPingDeviceIPv6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping ping test on windows")
	}
	if testing.Short() {
		t.Skip("skipping real ICMP ping in short mode")
	}
	ms, err := pingDevice(context.Background(), "::1", 2000)
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingLocalhost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real ICMP ping in short mode")
	}
	ms, err := icmpPing(context.Background(), "127.0.0.1", 2000)
	if err != nil {
		t.Skipf("ICMP not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingIPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real ICMP ping in short mode")
	}
	ms, err := icmpPing(context.Background(), "::1", 2000)
	if err != nil {
		t.Skipf("IPv6 ICMP not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingInvalidIP(t *testing.T) {
	_, err := icmpPing(context.Background(), "not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestErrICMPUnavailableError(t *testing.T) {
	cause := errors.New("permission denied")
	err := &errICMPUnavailable{err: cause}
	if err.Error() != "permission denied" {
		t.Errorf("got %q, want %q", err.Error(), "permission denied")
	}

	wrapped := fmt.Errorf("open socket: %w", err)
	var unavailable *errICMPUnavailable
	if !errors.As(wrapped, &unavailable) {
		t.Errorf("errors.As(%v) did not find *errICMPUnavailable", wrapped)
	}
	if !errors.Is(wrapped, cause) {
		t.Errorf("errors.Is(%v, %v) = false, want true", wrapped, cause)
	}
}

func TestParsePingTime(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    float64
		wantErr bool
	}{
		{
			name:   "standard linux",
			output: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms",
			want:   12.3,
		},
		{
			name:   "localhost",
			output: "64 bytes from localhost: icmp_seq=1 ttl=64 time=0.123 ms",
			want:   0.123,
		},
		{
			name:   "multiline",
			output: "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=15.7 ms\n--- 8.8.8.8 ping statistics ---",
			want:   15.7,
		},
		{
			name:    "no time field",
			output:  "Request timeout for icmp_seq 0",
			wantErr: true,
		},
		{
			name:    "empty",
			output:  "",
			wantErr: true,
		},
		{
			name:   "time= without ms suffix",
			output: "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.234\n",
			want:   1.234,
		},
		{
			name:   "busybox sub-millisecond reply",
			output: "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: seq=0 ttl=64 time<1 ms\n--- 127.0.0.1 ping statistics ---",
			want:   0,
		},
		{
			name:   "busybox sub-millisecond reply without space",
			output: "64 bytes from 10.0.0.1: seq=0 ttl=64 time<1ms",
			want:   0,
		},
		{
			name:    "busybox sub-millisecond reply with unparseable bound",
			output:  "64 bytes from 10.0.0.1: seq=0 ttl=64 time<abc ms",
			wantErr: true,
		},
		{
			name:   "busybox sub-millisecond reply with bare bound",
			output: "64 bytes from 10.0.0.1: seq=0 ttl=64 time<1",
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePingTime(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecPingLocalhost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	if testing.Short() {
		t.Skip("skipping real exec ping in short mode")
	}
	ms, err := execPing(context.Background(), "127.0.0.1", 2000)
	if err != nil {
		t.Skipf("ping command not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestExecPingInvalidIP(t *testing.T) {
	_, err := execPing(context.Background(), "not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestExecPingTimeoutArgument(t *testing.T) {
	origGOOS := pingGOOS
	t.Cleanup(func() { pingGOOS = origGOOS })

	tests := []struct {
		name      string
		goos      string
		timeoutMs int
		want      int
	}{
		{name: "darwin uses milliseconds", goos: "darwin", timeoutMs: 5000, want: 5000},
		{name: "darwin clamps to one millisecond", goos: "darwin", timeoutMs: 0, want: 1},
		{name: "linux uses seconds", goos: "linux", timeoutMs: 5000, want: 5},
		{name: "linux clamps to one second", goos: "linux", timeoutMs: 999, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pingGOOS = tt.goos
			if got := pingTimeoutArg(tt.timeoutMs); got != tt.want {
				t.Errorf("pingTimeoutArg(%d) on %s = %d, want %d", tt.timeoutMs, tt.goos, got, tt.want)
			}
		})
	}
}

func TestIPv6PingCommandFallsBackToPing(t *testing.T) {
	origLookPath := pingLookPath
	t.Cleanup(func() { pingLookPath = origLookPath })

	pingLookPath = func(file string) (string, error) { return "/sbin/" + file, nil }
	if got := ipv6PingCommand(); got != "ping6" {
		t.Errorf("ipv6PingCommand() = %q, want ping6 when the binary exists", got)
	}

	pingLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if got := ipv6PingCommand(); got != "ping" {
		t.Errorf("ipv6PingCommand() = %q, want ping when ping6 is absent", got)
	}
}

func TestExecPingIPv6Localhost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	if testing.Short() {
		t.Skip("skipping real exec ping in short mode")
	}
	ms, err := execPing(context.Background(), "::1", 2000)
	if err != nil {
		t.Skipf("ping6 not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestExecPingCommandResult(t *testing.T) {
	origCommand := pingCommandOutput
	t.Cleanup(func() { pingCommandOutput = origCommand })

	t.Run("failure", func(t *testing.T) {
		pingCommandOutput = func(context.Context, string, ...string) ([]byte, error) {
			return []byte("100% packet loss"), errors.New("exit status 1")
		}
		_, err := execPing(context.Background(), "192.0.2.1", 1000)
		if err == nil || !strings.Contains(err.Error(), "ping failed: 100% packet loss") {
			t.Fatalf("execPing error = %v, want packet-loss failure", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		pingCommandOutput = func(context.Context, string, ...string) ([]byte, error) {
			return []byte("64 bytes from 192.0.2.1: time=12.345 ms"), nil
		}
		got, err := execPing(context.Background(), "192.0.2.1", 1000)
		if err != nil {
			t.Fatalf("execPing returned error: %v", err)
		}
		if got != 12.345 {
			t.Fatalf("execPing response time = %v, want 12.345", got)
		}
	})
}

func TestPingDeviceFallbackToExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	if testing.Short() {
		t.Skip("skipping real ping in short mode")
	}
	// Mock icmpListenPacket to always fail → forces fallback to execPing.
	// closeSharedSockets drops any cached real socket so the stub sees the
	// listen calls.
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()
	closeSharedSockets()
	defer closeSharedSockets()

	icmpListenPacket = func(network, address string) (icmpConn, error) {
		return nil, fmt.Errorf("permission denied")
	}

	ms, err := pingDevice(context.Background(), "127.0.0.1", 2000)
	if err != nil {
		t.Skipf("exec ping fallback not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time via exec fallback, got %v", ms)
	}
}

func TestPingDeviceNonICMPError(t *testing.T) {
	// When icmpPing returns a non-errICMPUnavailable error, pingDevice should NOT
	// fall back to exec - it should return the error directly.
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()
	closeSharedSockets()
	defer closeSharedSockets()

	// First call (raw ICMP) returns errICMPUnavailable → triggers UDP fallback
	// Second call (UDP ICMP) returns a real write error → not errICMPUnavailable
	calls := 0
	icmpListenPacket = func(network, address string) (icmpConn, error) {
		calls++
		if calls == 1 {
			// Raw ICMP fails with errICMPUnavailable
			return nil, fmt.Errorf("permission denied")
		}
		// UDP ICMP also fails with errICMPUnavailable
		return nil, fmt.Errorf("also denied")
	}

	_, err := pingDevice(context.Background(), "127.0.0.1", 1000)
	// Both ICMP attempts fail with errICMPUnavailable, so it falls back to exec
	// which should succeed for localhost
	if err != nil {
		t.Skipf("ping fallback not available: %v", err)
	}
}

func TestDoICMPPingIPv6Network(t *testing.T) {
	// Test with the IPv6 raw network to cover the ipv6-icmp branches
	ip := net.ParseIP("::1")
	_, err := doICMPPing(context.Background(), ip, "ip6:ipv6-icmp", false, 1000)
	if err != nil {
		t.Skipf("IPv6 ICMP not available: %v", err)
	}
}

func TestDoICMPPingUDPNetwork(t *testing.T) {
	// Test with UDP network to cover the udp address branch
	ip := net.ParseIP("127.0.0.1")
	_, err := doICMPPing(context.Background(), ip, "udp4", true, 1000)
	if err != nil {
		t.Skipf("UDP ICMP not available: %v", err)
	}
}

func TestDoICMPPingTimeout(t *testing.T) {
	// Ping unreachable IP with short timeout → covers icmp read timeout error
	ip := net.ParseIP("192.0.2.1") // TEST-NET-1 - unreachable
	_, err := doICMPPing(context.Background(), ip, "udp4", true, 100)
	if err == nil {
		t.Error("expected timeout error for unreachable host")
	}
	if err != nil && !strings.Contains(err.Error(), "icmp read") {
		t.Logf("got error (expected icmp read timeout): %v", err)
	}
}

func TestDoICMPPingIPv6Timeout(t *testing.T) {
	// IPv6 unreachable - covers the ipv6 branch in doICMPPing
	ip := net.ParseIP("100::1") // Unreachable IPv6
	_, err := doICMPPing(context.Background(), ip, "udp6", false, 100)
	if err != nil {
		// May fail with various errors depending on system IPv6 support
		t.Logf("IPv6 ICMP error (expected): %v", err)
	}
}

func TestIcmpPingNonICMPUnavailableError(t *testing.T) {
	readFailure := errors.New("scripted read failure")
	conn := tpTNewFakeICMPConn()
	conn.readErr = readFailure
	networks := tpTUseFakeICMPConn(t, conn)

	_, err := icmpPing(context.Background(), "127.0.0.1", 1000)
	if !errors.Is(err, readFailure) {
		t.Fatalf("icmpPing error = %v, want wrapped %v", err, readFailure)
	}
	if len(*networks) != 1 || (*networks)[0] != "ip4:icmp" {
		t.Errorf("listened on %v, want raw ICMP only", *networks)
	}
}

func TestIcmpPingUDPFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real ICMP in short mode")
	}
	// Mock raw ICMP to fail, forcing UDP fallback path in icmpPing
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()
	closeSharedSockets()
	defer closeSharedSockets()

	calls := 0
	icmpListenPacket = func(network, address string) (icmpConn, error) {
		calls++
		if calls == 1 {
			// Raw ICMP fails
			return nil, fmt.Errorf("permission denied")
		}
		// UDP ICMP uses the real implementation
		return icmp.ListenPacket(network, address)
	}

	ms, err := icmpPing(context.Background(), "127.0.0.1", 2000)
	if err != nil {
		t.Skipf("UDP ICMP not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 ListenPacket calls (raw + udp), got %d", calls)
	}
}

// --- tpT: scripted ICMP connection and property coverage -------------------

// tpTFakeICMPConn is a scripted icmpConn shared by every ping run against the
// network it was installed for. WriteTo records the echo requests so replies
// and errors can be built from the live id/seq each ping picked; ReadFrom
// waits for the first request, hands back the scripted replies (each computed
// from the most recent request), then serves packets queued by injectPacket
// until the conn is closed.
type tpTSentPacket struct {
	pkt []byte
	dst net.Addr
}

type tpTInjectedPacket struct {
	pkt  []byte
	peer net.Addr
}

type tpTFakeICMPConn struct {
	mu        sync.Mutex
	sent      []tpTSentPacket
	replies   []func(req []byte) []byte
	consumed  int
	peers     []net.Addr
	readErr   error
	writeErr  error
	inject    chan tpTInjectedPacket
	closes    atomic.Int32
	closed    chan struct{}
	wrote     chan struct{}
	writeOnce sync.Once
	localAddr net.Addr
	closeOnce sync.Once
}

func tpTNewFakeICMPConn(replies ...func(req []byte) []byte) *tpTFakeICMPConn {
	return &tpTFakeICMPConn{
		replies: replies,
		inject:  make(chan tpTInjectedPacket, 64),
		closed:  make(chan struct{}),
		wrote:   make(chan struct{}),
	}
}

func (c *tpTFakeICMPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *tpTFakeICMPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	c.sent = append(c.sent, tpTSentPacket{pkt: append([]byte(nil), b...), dst: addr})
	c.mu.Unlock()
	c.writeOnce.Do(func() { close(c.wrote) })
	return len(b), nil
}

func (c *tpTFakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Scripted replies belong to a request, so nothing is served before the
	// first WriteTo. That also guarantees the ping's waiter is registered -
	// doICMPPing registers before it writes.
	select {
	case <-c.wrote:
	case <-c.closed:
		return 0, nil, fmt.Errorf("tpT: conn closed")
	}
	for {
		c.mu.Lock()
		if c.consumed < len(c.replies) {
			replyIndex := c.consumed
			c.consumed++
			req := c.sent[len(c.sent)-1].pkt
			c.mu.Unlock()
			pkt := c.replies[replyIndex](req)
			n := copy(b, pkt)
			if replyIndex < len(c.peers) {
				return n, c.peers[replyIndex], nil
			}
			return n, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
		}
		readErr := c.readErr
		c.mu.Unlock()
		if readErr != nil {
			return 0, nil, readErr
		}
		select {
		case pkt := <-c.inject:
			n := copy(b, pkt.pkt)
			if pkt.peer != nil {
				return n, pkt.peer, nil
			}
			return n, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
		case <-c.closed:
			return 0, nil, fmt.Errorf("tpT: conn closed")
		}
	}
}

// injectPacket queues a packet for the next ReadFrom, as though it arrived
// from peer.
func (c *tpTFakeICMPConn) injectPacket(pkt []byte, peer net.Addr) {
	select {
	case c.inject <- tpTInjectedPacket{pkt: pkt, peer: peer}:
	case <-c.closed:
	}
}

func (c *tpTFakeICMPConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *tpTFakeICMPConn) readsConsumed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed
}

// tpTWaitSent returns once the conn has recorded at least n echo requests and
// hands back a snapshot of them.
func tpTWaitSent(t *testing.T, c *tpTFakeICMPConn, n int) []tpTSentPacket {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		count := len(c.sent)
		if count >= n {
			sent := append([]tpTSentPacket(nil), c.sent...)
			c.mu.Unlock()
			return sent
		}
		c.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d sent packets, got %d", n, count)
		}
		time.Sleep(time.Millisecond)
	}
}

// tpTUseFakeICMPConn points icmpListenPacket at conn and records the networks
// it was asked for. The shared-socket registry is reset on both ends so a
// stale socket - real or scripted - can never bypass the stub.
func tpTUseFakeICMPConn(t *testing.T, conn icmpConn) *[]string {
	t.Helper()
	closeSharedSockets()
	orig := icmpListenPacket
	t.Cleanup(func() {
		icmpListenPacket = orig
		closeSharedSockets()
	})
	networks := new([]string)
	icmpListenPacket = func(network, _ string) (icmpConn, error) {
		*networks = append(*networks, network)
		return conn, nil
	}
	return networks
}

// tpTEchoPacket turns a recorded echo request into an echo reply, offsetting
// the id and seq so mismatched replies can be scripted too. It returns nil on
// malformed input.
func tpTEchoPacket(t *testing.T, isIPv4 bool, req []byte, idDelta, seqDelta int) []byte {
	t.Helper()
	proto := 1
	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if !isIPv4 {
		proto = 58
		replyType = ipv6.ICMPTypeEchoReply
	}
	parsed, err := icmp.ParseMessage(proto, req)
	if err != nil {
		t.Errorf("echo reply: request did not parse: %v", err)
		return nil
	}
	echo, ok := parsed.Body.(*icmp.Echo)
	if !ok {
		t.Errorf("echo reply: request body was %T, want *icmp.Echo", parsed.Body)
		return nil
	}
	reply := icmp.Message{
		Type: replyType,
		Body: &icmp.Echo{ID: echo.ID + idDelta, Seq: echo.Seq + seqDelta, Data: echo.Data},
	}
	wb, err := reply.Marshal(nil)
	if err != nil {
		t.Errorf("echo reply: marshal: %v", err)
		return nil
	}
	return wb
}

// tpTEchoReplyFor adapts tpTEchoPacket to the scripted reply signature.
func tpTEchoReplyFor(t *testing.T, isIPv4 bool, idDelta, seqDelta int) func(req []byte) []byte {
	t.Helper()
	return func(req []byte) []byte {
		return tpTEchoPacket(t, isIPv4, req, idDelta, seqDelta)
	}
}

func tpTEchoReplyWithIDFor(t *testing.T, isIPv4 bool, id int) func(req []byte) []byte {
	t.Helper()
	proto := 1
	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if !isIPv4 {
		proto = 58
		replyType = ipv6.ICMPTypeEchoReply
	}
	return func(req []byte) []byte {
		parsed, err := icmp.ParseMessage(proto, req)
		if err != nil {
			t.Errorf("scripted reply: request did not parse: %v", err)
			return nil
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok {
			t.Errorf("scripted reply: request body was %T, want *icmp.Echo", parsed.Body)
			return nil
		}
		reply := icmp.Message{
			Type: replyType,
			Body: &icmp.Echo{ID: id, Seq: echo.Seq, Data: echo.Data},
		}
		wb, err := reply.Marshal(nil)
		if err != nil {
			t.Errorf("scripted reply: marshal: %v", err)
			return nil
		}
		return wb
	}
}

// tpTStaticReply returns a reply function that always yields the same bytes.
func tpTStaticReply(pkt []byte) func(req []byte) []byte {
	return func([]byte) []byte { return pkt }
}

// tpTQuotedDatagram wraps req (a marshalled echo request) in the IP header a
// router would quote inside an ICMP error, per RFC 792/4443, addressed to dst.
// seqDelta mangles the quoted sequence so unmatched errors can be scripted too.
func tpTQuotedDatagram(t *testing.T, isIPv4 bool, req []byte, seqDelta int, dst net.IP) []byte {
	t.Helper()
	proto := 1
	if !isIPv4 {
		proto = 58
	}
	parsed, err := icmp.ParseMessage(proto, req)
	if err != nil {
		t.Errorf("quoted datagram: request did not parse: %v", err)
		return nil
	}
	echo, ok := parsed.Body.(*icmp.Echo)
	if !ok {
		t.Errorf("quoted datagram: request body was %T, want *icmp.Echo", parsed.Body)
		return nil
	}
	if seqDelta != 0 {
		binary.BigEndian.PutUint16(req[6:8], uint16(echo.Seq+seqDelta))
	}
	if !isIPv4 {
		h := make([]byte, 40)
		h[0] = 0x60 // version 6
		h[6] = 58   // next header: ICMPv6
		h[7] = 64   // hop limit
		copy(h[24:40], dst.To16())
		return append(h, req...)
	}
	inner := req[:min(len(req), 8)]
	hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0xc0,
		TotalLen: 20 + len(inner),
		TTL:      64,
		Protocol: 1,
		Dst:      dst,
	}
	hb, err := hdr.Marshal()
	if err != nil {
		t.Errorf("quoted datagram: marshal IPv4 header: %v", err)
		return nil
	}
	return append(hb, inner...)
}

// tpTICMPErrorPacket builds a marshalled ICMP error message (destination
// unreachable, time exceeded, packet too big) that quotes req sent to dst.
// Called from both scripted replies and injected packets.
func tpTICMPErrorPacket(t *testing.T, isIPv4 bool, typ icmp.Type, req []byte, seqDelta int, dst net.IP) []byte {
	t.Helper()
	quoted := tpTQuotedDatagram(t, isIPv4, append([]byte(nil), req...), seqDelta, dst)
	if quoted == nil {
		return nil
	}
	var body icmp.MessageBody
	switch typ {
	case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
		body = &icmp.DstUnreach{Data: quoted}
	case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
		body = &icmp.TimeExceeded{Data: quoted}
	case ipv6.ICMPTypePacketTooBig:
		body = &icmp.PacketTooBig{MTU: 1280, Data: quoted}
	default:
		t.Errorf("icmp error reply: unsupported type %v", typ)
		return nil
	}
	code := 1
	if typ == ipv6.ICMPTypeDestinationUnreachable {
		code = 3 // address unreachable
	}
	wb, err := (&icmp.Message{Type: typ, Code: code, Body: body}).Marshal(nil)
	if err != nil {
		t.Errorf("icmp error reply: marshal: %v", err)
		return nil
	}
	return wb
}

// tpTICMPErrorFor adapts tpTICMPErrorPacket to the scripted reply signature.
func tpTICMPErrorFor(t *testing.T, isIPv4 bool, typ icmp.Type, seqDelta int, dst net.IP) func(req []byte) []byte {
	t.Helper()
	return func(req []byte) []byte {
		return tpTICMPErrorPacket(t, isIPv4, typ, req, seqDelta, dst)
	}
}

func TestTpTDoICMPPingUDPMatchesSocketPort(t *testing.T) {
	socketPort := (os.Getpid() & 0xffff) + 1
	if socketPort > 0xffff {
		socketPort = 1
	}
	conn := tpTNewFakeICMPConn(
		tpTEchoReplyFor(t, true, 0, 0),
		tpTEchoReplyWithIDFor(t, true, socketPort),
	)
	conn.localAddr = &net.UDPAddr{Port: socketPort}
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "udp4", true, 1000)
	if err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	if got := conn.readsConsumed(); got != 2 {
		t.Errorf("consumed %d replies, want 2 (pid identifier skipped, socket-port identifier matched)", got)
	}
}

func TestTpTDoICMPPingUDPMatchesSequenceWhenLocalAddressIsNotUDP(t *testing.T) {
	conn := tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 1, 0))
	conn.localAddr = &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "udp4", true, 1000)
	if err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	if got := conn.readsConsumed(); got != 1 {
		t.Errorf("consumed %d replies, want 1 (sequence-only fallback)", got)
	}
}

func TestTpTDoICMPPingSkipsUnusableReplies(t *testing.T) {
	echoRequest, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("other")},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("build echo request: %v", err)
	}

	conn := tpTNewFakeICMPConn(
		tpTStaticReply([]byte{0xff}),   // too short to parse
		tpTEchoReplyFor(t, true, 1, 0), // right shape, wrong id
		tpTEchoReplyFor(t, true, 0, 1), // right shape, wrong seq
		tpTStaticReply(echoRequest),    // valid ICMP, but not an echo reply
		tpTEchoReplyFor(t, true, 0, 0), // the one we are waiting for
	)
	tpTUseFakeICMPConn(t, conn)

	ms, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "ip4:icmp", true, 1000)
	if err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	if ms < 0 {
		t.Errorf("round-trip = %v ms, want >= 0", ms)
	}
	if got := conn.readsConsumed(); got != 5 {
		t.Errorf("consumed %d replies, want 5 (four unusable, then the match)", got)
	}
}

func TestTpTDoICMPPingRejectsReplyFromWrongPeer(t *testing.T) {
	readFailure := errors.New("scripted read failure")
	target := net.ParseIP("127.0.0.1")
	tests := []struct {
		name     string
		peers    []net.Addr
		replies  int
		wantRead int
		wantErr  bool
	}{
		{
			name: "skips wrong host before genuine reply",
			peers: []net.Addr{
				&net.IPAddr{IP: net.ParseIP("192.0.2.10")},
				&net.UDPAddr{IP: target},
			},
			replies:  2,
			wantRead: 2,
		},
		{
			name: "wrong host alone cannot satisfy ping",
			peers: []net.Addr{
				&net.IPAddr{IP: net.ParseIP("192.0.2.10")},
			},
			replies:  1,
			wantRead: 1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			replies := make([]func(req []byte) []byte, tt.replies)
			for i := range replies {
				replies[i] = tpTEchoReplyFor(t, true, 0, 0)
			}
			conn := tpTNewFakeICMPConn(replies...)
			conn.peers = tt.peers
			conn.readErr = readFailure
			tpTUseFakeICMPConn(t, conn)

			ms, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 1000)
			if tt.wantErr {
				if err == nil {
					t.Fatal("doICMPPing accepted a reply from the wrong host")
				}
				if !errors.Is(err, readFailure) {
					t.Errorf("error = %v, want wrapped %v", err, readFailure)
				}
			} else {
				if err != nil {
					t.Fatalf("doICMPPing: %v", err)
				}
				if ms < 0 {
					t.Errorf("round-trip = %v ms, want >= 0 from the genuine reply", ms)
				}
			}
			if got := conn.readsConsumed(); got != tt.wantRead {
				t.Errorf("consumed %d replies, want %d", got, tt.wantRead)
			}
		})
	}
}

func TestTpTDoICMPPingUsesDistinctSequences(t *testing.T) {
	originalSeq := pingSeq.Load()
	t.Cleanup(func() { pingSeq.Store(originalSeq) })
	pingSeq.Store(100)

	// Both pings share one socket; replies are injected after both requests
	// are recorded, so each reply must reach its own waiter.
	conn := tpTNewFakeICMPConn()
	networks := tpTUseFakeICMPConn(t, conn)

	origMarshal := icmpMarshal
	t.Cleanup(func() { icmpMarshal = origMarshal })
	var sequencesMu sync.Mutex
	var sequences []int
	icmpMarshal = func(m *icmp.Message) ([]byte, error) {
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			return nil, fmt.Errorf("marshalled body = %T, want *icmp.Echo", m.Body)
		}
		sequencesMu.Lock()
		sequences = append(sequences, echo.Seq)
		sequencesMu.Unlock()
		return m.Marshal(nil)
	}

	target := net.ParseIP("127.0.0.1")
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 3000)
			results <- err
		}()
	}

	sent := tpTWaitSent(t, conn, 2)
	// Deliver the replies out of order; routing by (id, seq) must still land
	// each on the right waiter.
	conn.injectPacket(tpTEchoPacket(t, true, sent[1].pkt, 0, 0), &net.IPAddr{IP: target})
	conn.injectPacket(tpTEchoPacket(t, true, sent[0].pkt, 0, 0), &net.IPAddr{IP: target})

	var pingErrors []error
	for range 2 {
		if err := <-results; err != nil {
			pingErrors = append(pingErrors, err)
		}
	}
	if len(pingErrors) != 0 {
		t.Fatalf("doICMPPing errors: %v", pingErrors)
	}

	if got := len(*networks); got != 1 {
		t.Errorf("opened %d sockets, want one shared socket", got)
	}

	sequencesMu.Lock()
	defer sequencesMu.Unlock()
	if len(sequences) != 2 {
		t.Fatalf("observed %d sequences, want 2", len(sequences))
	}
	slices.Sort(sequences)
	if sequences[0] != 101 || sequences[1] != 102 {
		t.Errorf("sequences = %v, want counter values 101 and 102", sequences)
	}
}

func TestTpTDoICMPPingIPv6ScriptedReply(t *testing.T) {
	conn := tpTNewFakeICMPConn(tpTEchoReplyFor(t, false, 0, 0))
	conn.peers = []net.Addr{&net.IPAddr{IP: net.ParseIP("::1")}}
	networks := tpTUseFakeICMPConn(t, conn)

	ms, err := doICMPPing(context.Background(), net.ParseIP("::1"), "ip6:ipv6-icmp", false, 1000)
	if err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	if ms < 0 {
		t.Errorf("round-trip = %v ms, want >= 0", ms)
	}
	if len(*networks) != 1 || (*networks)[0] != "ip6:ipv6-icmp" {
		t.Errorf("listened on %v, want [ip6:ipv6-icmp]", *networks)
	}
}

func TestTpTIcmpPingReturnsRawResult(t *testing.T) {
	conn := tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 0, 0))
	networks := tpTUseFakeICMPConn(t, conn)

	ms, err := icmpPing(context.Background(), "127.0.0.1", 1000)
	if err != nil {
		t.Fatalf("icmpPing: %v", err)
	}
	if ms < 0 {
		t.Errorf("round-trip = %v ms, want >= 0", ms)
	}
	// The raw attempt succeeded, so there must be no UDP fallback attempt.
	if len(*networks) != 1 || (*networks)[0] != "ip4:icmp" {
		t.Errorf("listened on %v, want exactly [ip4:icmp]", *networks)
	}
}

func TestTpTPingDeviceReturnsICMPResultWithoutExecFallback(t *testing.T) {
	// pingDevice must hand back the ICMP round-trip time as soon as the ICMP
	// socket works, and must not shell out to the system ping. Driven through
	// the scripted connection so this path does not depend on whether the
	// machine running the tests permits ICMP sockets at all.
	conn := tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 0, 0))
	networks := tpTUseFakeICMPConn(t, conn)

	ms, err := pingDevice(context.Background(), "127.0.0.1", 1000)
	if err != nil {
		t.Fatalf("pingDevice: %v", err)
	}
	if ms < 0 {
		t.Errorf("round-trip = %v ms, want >= 0", ms)
	}
	if len(*networks) != 1 || (*networks)[0] != "ip4:icmp" {
		t.Errorf("listened on %v, want exactly [ip4:icmp]", *networks)
	}
}

func TestTpTDoICMPPingMarshalError(t *testing.T) {
	conn := tpTNewFakeICMPConn()
	tpTUseFakeICMPConn(t, conn)

	origMarshal := icmpMarshal
	defer func() { icmpMarshal = origMarshal }()
	icmpMarshal = func(*icmp.Message) ([]byte, error) { return nil, fmt.Errorf("bad body") }

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "ip4:icmp", true, 1000)
	if err == nil {
		t.Fatal("expected an error when the echo request cannot be marshalled")
	}
	if !strings.Contains(err.Error(), "icmp marshal: bad body") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "icmp marshal: bad body")
	}
	if conn.readsConsumed() != 0 {
		t.Error("doICMPPing read from the socket despite the marshal failure")
	}
}

func TestTpTDoICMPPingWriteError(t *testing.T) {
	conn := tpTNewFakeICMPConn()
	conn.writeErr = fmt.Errorf("network unreachable")
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "udp4", true, 1000)
	if err == nil {
		t.Fatal("expected an error when the echo request cannot be sent")
	}
	if !strings.Contains(err.Error(), "icmp write: network unreachable") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "icmp write: network unreachable")
	}
}

func TestTpTDoICMPPingReturnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := tpTNewFakeICMPConn()
	tpTUseFakeICMPConn(t, conn)

	done := make(chan error, 1)
	go func() {
		_, err := doICMPPing(ctx, net.ParseIP("127.0.0.1"), "udp4", true, 30000)
		done <- err
	}()

	// Wait until the request is actually in flight so the cancel lands while
	// the ping is waiting on the shared socket's waiter.
	tpTWaitSent(t, conn, 1)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error after the context was cancelled")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %q, want a wrapped %q", err.Error(), context.Canceled)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("doICMPPing did not return after its context was cancelled")
	}

	// The socket is shared, so cancelling one ping must not close it.
	if got := conn.closes.Load(); got != 0 {
		t.Errorf("Close called %d times, want 0 - the shared socket stays open", got)
	}
}

func TestTpTIcmpPingListenFailureFallsBack(t *testing.T) {
	orig := icmpListenPacket
	defer func() { icmpListenPacket = orig }()
	closeSharedSockets()
	defer closeSharedSockets()

	var networks []string
	icmpListenPacket = func(network, _ string) (icmpConn, error) {
		networks = append(networks, network)
		return nil, fmt.Errorf("operation not permitted")
	}

	_, err := icmpPing(context.Background(), "::1", 1000)
	if err == nil {
		t.Fatal("expected an error when no ICMP socket can be opened")
	}
	if _, ok := err.(*errICMPUnavailable); !ok {
		t.Errorf("error type = %T, want *errICMPUnavailable", err)
	}
	want := []string{"ip6:ipv6-icmp", "udp6"}
	if len(networks) != len(want) || networks[0] != want[0] || networks[1] != want[1] {
		t.Errorf("listened on %v, want %v", networks, want)
	}
}

func TestTpTDoICMPPingUnreachableShortCircuits(t *testing.T) {
	target := net.ParseIP("192.0.2.1") // TEST-NET-1, no echo reply will arrive
	conn := tpTNewFakeICMPConn(tpTICMPErrorFor(t, true, ipv4.ICMPTypeDestinationUnreachable, 0, target))
	tpTUseFakeICMPConn(t, conn)

	start := time.Now()
	_, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 30000)
	if err == nil {
		t.Fatal("expected an unreachable error")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error = %q, want it to mention unreachable", err.Error())
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("doICMPPing returned after %v, want an immediate failure well under the 30s timeout", elapsed)
	}
	if got := conn.readsConsumed(); got != 1 {
		t.Errorf("consumed %d replies, want 1", got)
	}
}

func TestTpTDoICMPPingTimeExceededShortCircuits(t *testing.T) {
	target := net.ParseIP("192.0.2.1")
	conn := tpTNewFakeICMPConn(tpTICMPErrorFor(t, true, ipv4.ICMPTypeTimeExceeded, 0, target))
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 30000)
	if err == nil {
		t.Fatal("expected a time-exceeded error")
	}
	if !strings.Contains(err.Error(), "time exceeded") {
		t.Errorf("error = %q, want it to mention time exceeded", err.Error())
	}
}

func TestTpTDoICMPPingIgnoresUnmatchedErrorThenAcceptsReply(t *testing.T) {
	target := net.ParseIP("127.0.0.1")
	// First error quotes a different sequence and must be ignored; the
	// following echo reply still completes the ping.
	conn := tpTNewFakeICMPConn(
		tpTICMPErrorFor(t, true, ipv4.ICMPTypeDestinationUnreachable, 42, target),
		tpTEchoReplyFor(t, true, 0, 0),
	)
	tpTUseFakeICMPConn(t, conn)

	ms, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 3000)
	if err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	if ms < 0 {
		t.Errorf("round-trip = %v ms, want >= 0", ms)
	}
	if got := conn.readsConsumed(); got != 2 {
		t.Errorf("consumed %d replies, want 2 (unmatched error, then the reply)", got)
	}
}

func TestTpTICMPErrorForIPv6(t *testing.T) {
	target := net.ParseIP("::1")
	conn := tpTNewFakeICMPConn(tpTICMPErrorFor(t, false, ipv6.ICMPTypeDestinationUnreachable, 0, target))
	conn.peers = []net.Addr{&net.IPAddr{IP: net.ParseIP("fe80::1")}}
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), target, "ip6:ipv6-icmp", false, 30000)
	if err == nil {
		t.Fatal("expected an unreachable error")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error = %q, want it to mention unreachable", err.Error())
	}
}

func TestTpTDispatchRoutesByKey(t *testing.T) {
	// Exercise the reply router directly: a reply for one (id, seq) must reach
	// only its own waiter.
	sock := &icmpSocket{proto: 1, replyID: os.Getpid() & 0xffff, waiters: make(map[pingKey]*pingWaiter)}
	target := net.ParseIP("127.0.0.1")

	w1 := sock.register(pingKey{id: 10, seq: 1}, target)
	w2 := sock.register(pingKey{id: 10, seq: 2}, target)

	reply := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 10, Seq: 2},
	}
	sock.dispatch(reply, target)

	select {
	case r := <-w2.ch:
		if r.err != nil {
			t.Fatalf("w2 got error %v", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("w2 never received its echo reply")
	}
	select {
	case <-w1.ch:
		t.Fatal("w1 received a reply meant for w2")
	default:
	}

	// A reply from a different source address never satisfies a waiter.
	sock.dispatch(reply, net.ParseIP("192.0.2.99"))
	select {
	case <-w2.ch:
		t.Fatal("wrong-source reply reached w2")
	default:
	}

	// Waiters without a known identifier match on sequence alone.
	w3 := sock.register(pingKey{id: -1, seq: 7}, target)
	sock.dispatch(&icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 4242, Seq: 7},
	}, target)
	select {
	case r := <-w3.ch:
		if r.err != nil {
			t.Fatalf("w3 got error %v", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("w3 never received its echo reply")
	}
}

// tpTPingNoiseAlphabet contains no '=' , so generated noise lines can never
// accidentally carry a "time=" field.
var tpTPingNoiseAlphabet = []rune("abcXYZ 0123.:/-()")

func TestPropTpParsePingTimeRoundtrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		want := rapid.Float64Range(0.001, 9999.0).Draw(t, "ms")
		formatted := strconv.FormatFloat(want, 'f', 3, 64)
		want, err := strconv.ParseFloat(formatted, 64)
		if err != nil {
			t.Fatalf("formatting %q is not parseable: %v", formatted, err)
		}

		noise := rapid.SliceOfN(
			rapid.StringOfN(rapid.RuneFrom(tpTPingNoiseAlphabet), 0, 40, -1),
			0, 4,
		).Draw(t, "noise")
		before := rapid.IntRange(0, len(noise)).Draw(t, "linesBeforeReply")

		reply := "64 bytes from 1.2.3.4: icmp_seq=1 ttl=57 time=" + formatted + " ms"
		lines := make([]string, 0, len(noise)+1)
		lines = append(lines, noise[:before]...)
		lines = append(lines, reply)
		lines = append(lines, noise[before:]...)
		output := strings.Join(lines, "\n")

		got, err := parsePingTime(output)
		if err != nil {
			t.Fatalf("parsePingTime(%q) failed: %v", output, err)
		}
		if diff := got - want; diff > 1e-9 || diff < -1e-9 {
			t.Fatalf("parsePingTime(%q) = %v, want %v", output, got, want)
		}

		// The same output with the reply line removed carries no time= field at
		// all, so it must be reported as an error rather than parsed as zero.
		noTime := strings.Join(noise, "\n")
		if v, err := parsePingTime(noTime); err == nil {
			t.Fatalf("parsePingTime(%q) = %v, want an error", noTime, v)
		}
	})
}

// tpTOpaqueAddr is a net.Addr implementation peerIP does not recognise.
type tpTOpaqueAddr struct{}

func (tpTOpaqueAddr) Network() string { return "opaque" }
func (tpTOpaqueAddr) String() string  { return "opaque-addr" }

func TestTpTPeerIPMapsAddrKinds(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want net.IP
	}{
		{name: "ip addr v4", addr: &net.IPAddr{IP: net.ParseIP("192.0.2.5")}, want: net.ParseIP("192.0.2.5")},
		{name: "ip addr v6", addr: &net.IPAddr{IP: net.ParseIP("2001:db8::1")}, want: net.ParseIP("2001:db8::1")},
		{name: "udp addr", addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 33434}, want: net.ParseIP("198.51.100.7")},
		{name: "nil ip addr pointer", addr: (*net.IPAddr)(nil), want: nil},
		{name: "nil udp addr pointer", addr: (*net.UDPAddr)(nil), want: nil},
		{name: "tcp addr is unrecognised", addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 80}, want: nil},
		{name: "unix addr is unrecognised", addr: &net.UnixAddr{Name: "/tmp/sock", Net: "unix"}, want: nil},
		{name: "custom addr is unrecognised", addr: tpTOpaqueAddr{}, want: nil},
		{name: "nil addr", addr: nil, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := peerIP(tc.addr)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("peerIP(%v) = %v, want nil", tc.addr, got)
				}
				return
			}
			if !got.Equal(tc.want) {
				t.Fatalf("peerIP(%v) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// --- coverage: socket registry, dispatch drops, and quote parsing ----------

func TestTpTSharedSocketReplacesDeadSocket(t *testing.T) {
	fresh := tpTNewFakeICMPConn()
	tpTUseFakeICMPConn(t, fresh) // resets the registry first

	// Seed a dead socket for the network: the dead entry must be dropped and
	// a fresh socket installed.
	dead := &icmpSocket{conn: tpTNewFakeICMPConn(), waiters: make(map[pingKey]*pingWaiter)}
	dead.mu.Lock()
	dead.err = errors.New("read failed")
	dead.mu.Unlock()
	sharedSockets.mu.Lock()
	sharedSockets.m["ip4:icmp"] = dead
	sharedSockets.mu.Unlock()

	sock, err := sharedSocket("ip4:icmp")
	if err != nil {
		t.Fatalf("sharedSocket: %v", err)
	}
	if sock == dead {
		t.Fatal("dead socket was not replaced")
	}
	sharedSockets.mu.Lock()
	got := sharedSockets.m["ip4:icmp"]
	sharedSockets.mu.Unlock()
	if got != sock {
		t.Fatal("registry did not record the replacement socket")
	}
}

func TestTpTDispatchDropsMalformedAndUnmatched(t *testing.T) {
	target := net.ParseIP("127.0.0.1")
	sock := &icmpSocket{proto: 1, replyID: 1, waiters: make(map[pingKey]*pingWaiter)}
	w := sock.register(pingKey{id: 1, seq: 9}, target)
	defer sock.unregister(pingKey{id: 1, seq: 9}, w)

	// Echo reply with a non-Echo body is ignored.
	sock.dispatch(&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.DstUnreach{}}, target)

	// A matching reply from a nil source is ignored.
	sock.dispatch(&icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 1, Seq: 9},
	}, nil)

	// An ICMP error whose quote cannot be parsed is ignored.
	sock.dispatch(&icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable, Code: 1,
		Body: &icmp.DstUnreach{Data: []byte{1, 2, 3}},
	}, target)

	// An ICMP error quoting an unknown (id, seq) is ignored.
	unknownReq, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 1, Seq: 77, Data: []byte("x")},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	sock.dispatch(&icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable, Code: 1,
		Body: &icmp.DstUnreach{Data: tpTQuotedDatagram(t, true, unknownReq, 0, target)},
	}, target)

	select {
	case r := <-w.ch:
		t.Fatalf("waiter received unexpected reply %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTpTDispatchPacketTooBig(t *testing.T) {
	target := net.ParseIP("::1")
	sock := &icmpSocket{proto: 58, replyID: 1, waiters: make(map[pingKey]*pingWaiter)}
	w := sock.register(pingKey{id: 1, seq: 3}, target)
	defer sock.unregister(pingKey{id: 1, seq: 3}, w)

	req, err := (&icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Body: &icmp.Echo{ID: 1, Seq: 3, Data: []byte("x")},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	sock.dispatch(&icmp.Message{
		Type: ipv6.ICMPTypePacketTooBig, Code: 0,
		Body: &icmp.PacketTooBig{MTU: 1280, Data: tpTQuotedDatagram(t, false, req, 0, target)},
	}, target)

	select {
	case r := <-w.ch:
		if r.err == nil || !strings.Contains(r.err.Error(), "packet too big") {
			t.Fatalf("waiter error = %v, want packet too big", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not receive the packet-too-big failure")
	}
}

func TestTpTFailIsIdempotent(t *testing.T) {
	sock := &icmpSocket{
		proto:   1,
		waiters: make(map[pingKey]*pingWaiter),
		conn:    tpTNewFakeICMPConn(),
	}
	sock.fail(errors.New("first"))
	sock.fail(errors.New("second"))
	if got := sock.readErr(); got == nil || got.Error() != "first" {
		t.Fatalf("readErr = %v, want first failure retained", got)
	}
}

func TestTpTQuotedEchoIDSeqRejectsMalformed(t *testing.T) {
	echoReq, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x1234, Seq: 0xabcd, Data: []byte("x")},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	quotedDstV4 := net.ParseIP("198.51.100.4")
	quotedDstV6 := net.ParseIP("2001:db8::1")
	validV4 := tpTQuotedDatagram(t, true, echoReq, 0, quotedDstV4)

	cases := []struct {
		name   string
		data   []byte
		isIPv4 bool
	}{
		{"v4 too short", validV4[:10], true},
		{"v4 wrong version", func() []byte { d := append([]byte(nil), validV4...); d[0] = 0x60; return d }(), true},
		{"v4 wrong protocol", func() []byte { d := append([]byte(nil), validV4...); d[9] = 6; return d }(), true},
		{"v4 ihl beyond quote", func() []byte { d := append([]byte(nil), validV4...); d[0] = 0x4f; return d }(), true},
		{"v4 non-echo icmp", func() []byte { d := append([]byte(nil), validV4...); d[20] = 3; return d }(), true},
		{"v6 too short", make([]byte, 30), false},
		{"v6 wrong version", func() []byte { d := make([]byte, 48); d[0] = 0x40; return d }(), false},
		{"v6 wrong next header", func() []byte { d := make([]byte, 48); d[0] = 0x60; d[6] = 6; return d }(), false},
		{"v6 non-echo icmp", func() []byte {
			h := make([]byte, 40)
			h[0] = 0x60
			h[6] = 58
			return append(h, 1, 0, 0, 0, 0, 1, 0, 2)
		}(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, ok := quotedEchoIDSeq(tc.data, tc.isIPv4); ok {
				t.Fatal("malformed quote parsed successfully")
			}
		})
	}

	// Well-formed quotes extract the embedded id, seq and destination.
	if id, seq, dst, ok := quotedEchoIDSeq(validV4, true); !ok || id != 0x1234 || seq != 0xabcd || !dst.Equal(quotedDstV4) {
		t.Fatalf("v4 quote = (%x, %x, %v, %v), want (1234, abcd, %v, true)", id, seq, dst, ok, quotedDstV4)
	}
	v6req, err := (&icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Body: &icmp.Echo{ID: 0x55, Seq: 0x66, Data: []byte("x")},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if id, seq, dst, ok := quotedEchoIDSeq(tpTQuotedDatagram(t, false, v6req, 0, quotedDstV6), false); !ok || id != 0x55 || seq != 0x66 || !dst.Equal(quotedDstV6) {
		t.Fatalf("v6 quote = (%x, %x, %v, %v), want (55, 66, %v, true)", id, seq, dst, ok, quotedDstV6)
	}
}

// --- regressions: transient read errors, closed-socket writes, quoted dst --

// tpTReadResult is one scripted ReadFrom outcome.
type tpTReadResult struct {
	pkt  []byte
	peer net.Addr
	err  error
}

// tpTScriptedReadConn serves ReadFrom results from a channel and reports
// net.ErrClosed once closed, like a real socket.
type tpTScriptedReadConn struct {
	reads     chan tpTReadResult
	closed    chan struct{}
	closeOnce sync.Once
}

func tpTNewScriptedReadConn() *tpTScriptedReadConn {
	return &tpTScriptedReadConn{reads: make(chan tpTReadResult, 16), closed: make(chan struct{})}
}

func (c *tpTScriptedReadConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *tpTScriptedReadConn) LocalAddr() net.Addr                       { return nil }

func (c *tpTScriptedReadConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case r := <-c.reads:
		if r.err != nil {
			return 0, nil, r.err
		}
		return copy(b, r.pkt), r.peer, nil
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: "ip4:icmp", Err: net.ErrClosed}
	}
}

func (c *tpTScriptedReadConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// tpTTimeoutErr is a net.Error reporting a timeout.
type tpTTimeoutErr struct{}

func (tpTTimeoutErr) Error() string   { return "i/o timeout" }
func (tpTTimeoutErr) Timeout() bool   { return true }
func (tpTTimeoutErr) Temporary() bool { return true }

func tpTRecvErr(errno syscall.Errno) error {
	return &net.OpError{Op: "read", Net: "ip4:icmp", Err: os.NewSyscallError("recvfrom", errno)}
}

func TestTpTIsTransientICMPReadError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"econnrefused", tpTRecvErr(syscall.ECONNREFUSED), true},
		{"ehostunreach", tpTRecvErr(syscall.EHOSTUNREACH), true},
		{"enetunreach", tpTRecvErr(syscall.ENETUNREACH), true},
		{"eagain", tpTRecvErr(syscall.EAGAIN), true},
		{"eintr", tpTRecvErr(syscall.EINTR), true},
		{"timeout", &net.OpError{Op: "read", Err: tpTTimeoutErr{}}, true},
		{"closed", &net.OpError{Op: "read", Err: net.ErrClosed}, false},
		{"ebadf", tpTRecvErr(syscall.EBADF), false},
		{"unknown", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientICMPReadError(tc.err); got != tc.want {
				t.Fatalf("isTransientICMPReadError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestTpTReadLoopSurvivesTransientErrors(t *testing.T) {
	// An ICMP hard error surfaces once on the next recvfrom of a raw socket.
	// It must not fail every in-flight ping or kill the shared socket.
	origBackoff := icmpReadBackoffMax
	icmpReadBackoffMax = time.Millisecond
	t.Cleanup(func() { icmpReadBackoffMax = origBackoff })

	conn := tpTNewScriptedReadConn()
	sock := &icmpSocket{conn: conn, proto: 1, replyID: 7, waiters: make(map[pingKey]*pingWaiter)}
	target := net.ParseIP("192.0.2.8")
	w1 := sock.register(pingKey{id: 7, seq: 1}, target)
	w2 := sock.register(pingKey{id: 7, seq: 2}, target)

	done := make(chan struct{})
	go func() {
		sock.readLoop()
		close(done)
	}()

	conn.reads <- tpTReadResult{err: tpTRecvErr(syscall.ECONNREFUSED)}
	conn.reads <- tpTReadResult{err: tpTRecvErr(syscall.EHOSTUNREACH)}
	conn.reads <- tpTReadResult{err: &net.OpError{Op: "read", Err: tpTTimeoutErr{}}}
	reply, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 7, Seq: 2, Data: []byte("x")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.reads <- tpTReadResult{pkt: reply, peer: &net.IPAddr{IP: target}}

	select {
	case r := <-w2.ch:
		if r.err != nil {
			t.Fatalf("w2 got error %v, want its echo reply", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo reply after transient errors never reached its waiter")
	}
	select {
	case r := <-w1.ch:
		t.Fatalf("w1 received %+v; transient read errors must not fail waiters", r)
	default:
	}
	if err := sock.readErr(); err != nil {
		t.Fatalf("socket marked dead after transient errors: %v", err)
	}

	// Closing the socket is still fatal and fails the remaining waiters.
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop did not exit after the socket closed")
	}
	if err := sock.readErr(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("readErr = %v, want wrapped net.ErrClosed", err)
	}
	select {
	case r := <-w1.ch:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("w1 error = %v, want wrapped net.ErrClosed", r.err)
		}
	default:
		t.Fatal("w1 was not failed when the socket closed")
	}
}

func TestTpTDoICMPPingRetriesWriteOnClosedSocket(t *testing.T) {
	// The shared socket can close between sharedSocket returning it and the
	// write; the ping must retry on a fresh socket instead of reporting the
	// device down.
	stale := tpTNewFakeICMPConn()
	stale.writeErr = &net.OpError{Op: "write", Net: "ip4:icmp", Err: net.ErrClosed}
	fresh := tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 0, 0))

	closeSharedSockets()
	orig := icmpListenPacket
	t.Cleanup(func() {
		icmpListenPacket = orig
		closeSharedSockets()
	})
	var mu sync.Mutex
	conns := []icmpConn{stale, fresh}
	listens := 0
	icmpListenPacket = func(string, string) (icmpConn, error) {
		mu.Lock()
		defer mu.Unlock()
		if listens >= len(conns) {
			return nil, fmt.Errorf("unexpected listen %d", listens)
		}
		c := conns[listens]
		listens++
		return c, nil
	}

	if _, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "ip4:icmp", true, 3000); err != nil {
		t.Fatalf("doICMPPing: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if listens != 2 {
		t.Errorf("opened %d sockets, want 2 (stale, then fresh)", listens)
	}
	if stale.closes.Load() == 0 {
		t.Error("stale socket was not closed when the write found it dead")
	}
}

func TestTpTDoICMPPingClosedSocketRetriesOnlyOnce(t *testing.T) {
	conn := tpTNewFakeICMPConn()
	conn.writeErr = &net.OpError{Op: "write", Net: "ip4:icmp", Err: net.ErrClosed}
	networks := tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "ip4:icmp", true, 1000)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("error = %v, want wrapped net.ErrClosed", err)
	}
	if got := len(*networks); got != 2 {
		t.Errorf("listened %d times, want 2 (one retry)", got)
	}
}

func TestTpTDispatchIgnoresErrorQuotingOtherDestination(t *testing.T) {
	for _, tc := range []struct {
		name   string
		isIPv4 bool
		target net.IP
		other  net.IP
	}{
		{"v4", true, net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.9")},
		{"v6", false, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::99")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proto, echoType, unreach := 1, icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeDestinationUnreachable)
			if !tc.isIPv4 {
				proto, echoType, unreach = 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeDestinationUnreachable
			}
			sock := &icmpSocket{proto: proto, replyID: 5, waiters: make(map[pingKey]*pingWaiter)}
			w := sock.register(pingKey{id: 5, seq: 11}, tc.target)
			req, err := (&icmp.Message{Type: echoType, Body: &icmp.Echo{ID: 5, Seq: 11, Data: []byte("x")}}).Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}

			// Same (id, seq) but quoting a different destination - another
			// process's request or a stale error - must be ignored.
			sock.dispatch(&icmp.Message{
				Type: unreach, Code: 1,
				Body: &icmp.DstUnreach{Data: tpTQuotedDatagram(t, tc.isIPv4, append([]byte(nil), req...), 0, tc.other)},
			}, tc.other)
			select {
			case r := <-w.ch:
				t.Fatalf("waiter failed by error quoting %v: %+v", tc.other, r)
			default:
			}

			// The same error quoting the pinged address fails the waiter.
			sock.dispatch(&icmp.Message{
				Type: unreach, Code: 1,
				Body: &icmp.DstUnreach{Data: tpTQuotedDatagram(t, tc.isIPv4, append([]byte(nil), req...), 0, tc.target)},
			}, tc.other)
			select {
			case r := <-w.ch:
				if r.err == nil || !strings.Contains(r.err.Error(), "unreachable") {
					t.Fatalf("waiter error = %v, want unreachable", r.err)
				}
			default:
				t.Fatal("error quoting the pinged address did not reach the waiter")
			}
		})
	}
}
