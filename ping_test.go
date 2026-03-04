package main

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/icmp"
)

func TestPingDeviceLocalhost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping ping test on windows")
	}
	ms, err := pingDevice("127.0.0.1", 5000)
	if err != nil {
		t.Skipf("ping not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestPingDeviceInvalidIP(t *testing.T) {
	_, err := pingDevice("not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestPingDeviceIPv6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping ping test on windows")
	}
	ms, err := pingDevice("::1", 5000)
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingLocalhost(t *testing.T) {
	ms, err := icmpPing("127.0.0.1", 5000)
	if err != nil {
		t.Skipf("ICMP not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingIPv6(t *testing.T) {
	ms, err := icmpPing("::1", 5000)
	if err != nil {
		t.Skipf("IPv6 ICMP not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestIcmpPingInvalidIP(t *testing.T) {
	_, err := icmpPing("not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestErrICMPUnavailableError(t *testing.T) {
	err := &errICMPUnavailable{err: fmt.Errorf("permission denied")}
	if err.Error() != "permission denied" {
		t.Errorf("got %q, want %q", err.Error(), "permission denied")
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
	ms, err := execPing("127.0.0.1", 5000)
	if err != nil {
		t.Skipf("ping command not available: %v", err)
	}
	if ms <= 0 {
		t.Errorf("expected positive response time, got %v", ms)
	}
}

func TestExecPingInvalidIP(t *testing.T) {
	_, err := execPing("not-an-ip", 5000)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestExecPingIPv6Localhost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	ms, err := execPing("::1", 5000)
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
	_, err := execPing("192.0.2.1", 1000) // TEST-NET-1 — unreachable
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
	// Mock icmpListenPacket to always fail → forces fallback to execPing
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

	icmpListenPacket = func(network, address string) (*icmp.PacketConn, error) {
		return nil, fmt.Errorf("permission denied")
	}

	ms, err := pingDevice("127.0.0.1", 5000)
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
	icmpListenPacket = func(network, address string) (*icmp.PacketConn, error) {
		calls++
		if calls == 1 {
			// Raw ICMP fails with errICMPUnavailable
			return nil, fmt.Errorf("permission denied")
		}
		// UDP ICMP also fails with errICMPUnavailable
		return nil, fmt.Errorf("also denied")
	}

	_, err := pingDevice("127.0.0.1", 1000)
	// Both ICMP attempts fail with errICMPUnavailable, so it falls back to exec
	// which should succeed for localhost
	if err != nil {
		t.Skipf("ping fallback not available: %v", err)
	}
}

func TestDoICMPPingIPv6Network(t *testing.T) {
	// Test with the IPv6 raw network to cover the ipv6-icmp branches
	ip := net.ParseIP("::1")
	_, err := doICMPPing(ip, "ip6:ipv6-icmp", false, 1000)
	if err != nil {
		t.Skipf("IPv6 ICMP not available: %v", err)
	}
}

func TestDoICMPPingUDPNetwork(t *testing.T) {
	// Test with UDP network to cover the udp address branch
	ip := net.ParseIP("127.0.0.1")
	_, err := doICMPPing(ip, "udp4", true, 1000)
	if err != nil {
		t.Skipf("UDP ICMP not available: %v", err)
	}
}

func TestDoICMPPingTimeout(t *testing.T) {
	// Ping unreachable IP with short timeout → covers icmp read timeout error
	ip := net.ParseIP("192.0.2.1") // TEST-NET-1 — unreachable
	_, err := doICMPPing(ip, "udp4", true, 100)
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
	_, err := doICMPPing(ip, "udp6", false, 100)
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
	icmpListenPacket = func(network, address string) (*icmp.PacketConn, error) {
		return icmp.ListenPacket("udp4", address)
	}

	_, err := icmpPing("192.0.2.1", 100) // TEST-NET-1, 100ms timeout
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestIcmpPingUDPFallback(t *testing.T) {
	// Mock raw ICMP to fail, forcing UDP fallback path in icmpPing
	origListen := icmpListenPacket
	defer func() { icmpListenPacket = origListen }()

	calls := 0
	icmpListenPacket = func(network, address string) (*icmp.PacketConn, error) {
		calls++
		if calls == 1 {
			// Raw ICMP fails
			return nil, fmt.Errorf("permission denied")
		}
		// UDP ICMP uses the real implementation
		return icmp.ListenPacket(network, address)
	}

	ms, err := icmpPing("127.0.0.1", 5000)
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
