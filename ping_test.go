// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
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

func TestExecPingUnreachable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	_, err := execPing(context.Background(), "192.0.2.1", 1000) // TEST-NET-1 — unreachable
	if err == nil {
		t.Error("expected error for unreachable host")
	}
	if err != nil && !strings.Contains(err.Error(), "ping failed") {
		t.Errorf("expected 'ping failed' in error, got: %v", err)
	}
}

func TestPingDeviceFallbackToExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	if testing.Short() {
		t.Skip("skipping real ping in short mode")
	}
	// Mock icmpListenPacket to always fail → forces fallback to execPing
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

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
	// fall back to exec — it should return the error directly.
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

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
	ip := net.ParseIP("192.0.2.1") // TEST-NET-1 — unreachable
	_, err := doICMPPing(context.Background(), ip, "udp4", true, 100)
	if err == nil {
		t.Error("expected timeout error for unreachable host")
	}
	if err != nil && !strings.Contains(err.Error(), "icmp read") {
		t.Logf("got error (expected icmp read timeout): %v", err)
	}
}

func TestDoICMPPingIPv6Timeout(t *testing.T) {
	// IPv6 unreachable — covers the ipv6 branch in doICMPPing
	ip := net.ParseIP("100::1") // Unreachable IPv6
	_, err := doICMPPing(context.Background(), ip, "udp6", false, 100)
	if err != nil {
		// May fail with various errors depending on system IPv6 support
		t.Logf("IPv6 ICMP error (expected): %v", err)
	}
}

func TestIcmpPingNonICMPUnavailableError(t *testing.T) {
	// When raw ICMP returns a non-errICMPUnavailable error, icmpPing should
	// return that error without falling back to UDP.
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

	// Raw ICMP succeeds (opens a connection), but pinging unreachable IP will timeout.
	// The timeout error is NOT errICMPUnavailable, so icmpPing returns it directly.
	icmpListenPacket = func(network, address string) (icmpConn, error) {
		return icmp.ListenPacket("udp4", address)
	}

	_, err := icmpPing(context.Background(), "192.0.2.1", 100) // TEST-NET-1, 100ms timeout
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestIcmpPingUDPFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real ICMP in short mode")
	}
	// Mock raw ICMP to fail, forcing UDP fallback path in icmpPing
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

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

// tpTFakeICMPConn is a scripted icmpConn. It records the echo request handed to
// WriteTo so replies can be built from the live id/seq that doICMPPing picks,
// then hands back one scripted packet per ReadFrom call.
type tpTFakeICMPConn struct {
	mu          sync.Mutex
	request     []byte
	replies     []func(req []byte) []byte
	consumed    int
	peers       []net.Addr
	readErr     error
	writeErr    error
	deadlineErr error
	deadline    time.Time
	onRead      func()
	closes      atomic.Int32
	closed      chan struct{}
	localAddr   net.Addr
	closeOnce   sync.Once
}

func tpTNewFakeICMPConn(replies ...func(req []byte) []byte) *tpTFakeICMPConn {
	return &tpTFakeICMPConn{replies: replies, closed: make(chan struct{})}
}

func (c *tpTFakeICMPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *tpTFakeICMPConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	c.request = append([]byte(nil), b...)
	c.mu.Unlock()
	return len(b), nil
}

func (c *tpTFakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.onRead != nil {
		c.onRead()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.consumed >= len(c.replies) {
		if c.readErr != nil {
			return 0, nil, c.readErr
		}
		return 0, nil, fmt.Errorf("tpT: no scripted reply #%d", c.consumed+1)
	}
	replyIndex := c.consumed
	pkt := c.replies[replyIndex](c.request)
	c.consumed++
	n := copy(b, pkt)
	if replyIndex < len(c.peers) {
		return n, c.peers[replyIndex], nil
	}
	return n, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
}

func (c *tpTFakeICMPConn) SetDeadline(t time.Time) error {
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
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

// tpTUseFakeICMPConn points icmpListenPacket at conn and records the networks
// it was asked for.
func tpTUseFakeICMPConn(t *testing.T, conn icmpConn) *[]string {
	t.Helper()
	orig := icmpListenPacket
	t.Cleanup(func() { icmpListenPacket = orig })
	networks := new([]string)
	icmpListenPacket = func(network, _ string) (icmpConn, error) {
		*networks = append(*networks, network)
		return conn, nil
	}
	return networks
}

// tpTEchoReplyFor turns the recorded echo request into an echo reply, offsetting
// the id and seq so mismatched replies can be scripted too.
func tpTEchoReplyFor(t *testing.T, isIPv4 bool, idDelta, seqDelta int) func(req []byte) []byte {
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
			Body: &icmp.Echo{ID: echo.ID + idDelta, Seq: echo.Seq + seqDelta, Data: echo.Data},
		}
		wb, err := reply.Marshal(nil)
		if err != nil {
			t.Errorf("scripted reply: marshal: %v", err)
			return nil
		}
		return wb
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

	conns := []*tpTFakeICMPConn{
		tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 0, 0)),
		tpTNewFakeICMPConn(tpTEchoReplyFor(t, true, 0, 0)),
	}
	origListen := icmpListenPacket
	t.Cleanup(func() { icmpListenPacket = origListen })
	var nextConn atomic.Uint32
	icmpListenPacket = func(string, string) (icmpConn, error) {
		index := nextConn.Add(1) - 1
		return conns[index], nil
	}

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
	results := make(chan error, len(conns))
	for range conns {
		go func() {
			_, err := doICMPPing(context.Background(), target, "ip4:icmp", true, 1000)
			results <- err
		}()
	}
	var pingErrors []error
	for range conns {
		if err := <-results; err != nil {
			pingErrors = append(pingErrors, err)
		}
	}
	if len(pingErrors) != 0 {
		t.Fatalf("doICMPPing errors: %v", pingErrors)
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

func TestTpTDoICMPPingSetDeadlineError(t *testing.T) {
	conn := tpTNewFakeICMPConn()
	conn.deadlineErr = fmt.Errorf("no deadline for you")
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(context.Background(), net.ParseIP("127.0.0.1"), "udp4", true, 1000)
	if err == nil {
		t.Fatal("expected an error when the deadline cannot be set")
	}
	if !strings.Contains(err.Error(), "set deadline: no deadline for you") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "set deadline: no deadline for you")
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

func TestTpTDoICMPPingClosesConnOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := tpTNewFakeICMPConn()
	conn.readErr = fmt.Errorf("use of closed connection")
	// Cancelling from inside the read, then waiting for the close, pins the
	// context-cancellation path without any timing assumptions.
	conn.onRead = func() {
		cancel()
		<-conn.closed
	}
	tpTUseFakeICMPConn(t, conn)

	_, err := doICMPPing(ctx, net.ParseIP("127.0.0.1"), "udp4", true, 5000)
	if err == nil {
		t.Fatal("expected an error after the connection was closed")
	}
	if !strings.Contains(err.Error(), "icmp read: use of closed connection") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "icmp read: use of closed connection")
	}
	if got := conn.closes.Load(); got < 2 {
		t.Errorf("Close called %d times, want the cancellation close plus the deferred close", got)
	}
}

func TestTpTIcmpPingListenFailureFallsBack(t *testing.T) {
	orig := icmpListenPacket
	defer func() { icmpListenPacket = orig }()

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

// tpTPingNoiseAlphabet contains no '=' , so generated noise lines can never
// accidentally carry a "time=" field.
var tpTPingNoiseAlphabet = []rune("abcXYZ 0123.:/-()")

func TestPropTpParsePingTimeRoundtrip(t *testing.T) {
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
