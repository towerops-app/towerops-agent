package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpPing sends a single ICMP echo request and returns the round-trip time in milliseconds.
// Tries raw ICMP sockets first (requires CAP_NET_RAW or root), then falls back to
// unprivileged UDP-based ICMP (requires ping_group_range sysctl).
func icmpPing(ip string, timeoutMs int) (float64, error) {
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
	ms, err := doICMPPing(parsedIP, rawNet, isIPv4, timeoutMs)
	if err == nil {
		return ms, nil
	}
	if _, ok := err.(*errICMPUnavailable); !ok {
		return 0, err
	}

	// Fall back to unprivileged UDP ICMP (works with ping_group_range sysctl)
	var udpNet string
	if isIPv4 {
		udpNet = "udp4"
	} else {
		udpNet = "udp6"
	}
	return doICMPPing(parsedIP, udpNet, isIPv4, timeoutMs)
}

// doICMPPing performs an ICMP ping over the given network type.
func doICMPPing(ip net.IP, network string, isIPv4 bool, timeoutMs int) (float64, error) {
	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return 0, &errICMPUnavailable{err: fmt.Errorf("icmp listen %s: %w", network, err)}
	}
	defer func() { _ = conn.Close() }()

	var msgType icmp.Type
	var proto int
	if isIPv4 {
		msgType = ipv4.ICMPTypeEcho
		proto = 1
	} else {
		msgType = ipv6.ICMPTypeEchoRequest
		proto = 58
	}

	id := os.Getpid() & 0xffff
	msg := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  1,
			Data: []byte("towerops"),
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("icmp marshal: %w", err)
	}

	// Destination address type depends on network
	var dst net.Addr
	if strings.HasPrefix(network, "udp") {
		dst = &net.UDPAddr{IP: ip}
	} else {
		dst = &net.IPAddr{IP: ip}
	}

	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return 0, fmt.Errorf("icmp write: %w", err)
	}

	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, fmt.Errorf("icmp read: %w", err)
		}
		elapsed := time.Since(start)

		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.ID != id {
				continue
			}
			return float64(elapsed.Microseconds()) / 1000.0, nil
		}
	}
}

// errICMPUnavailable is returned when the ICMP socket can't be opened.
// This triggers a fallback to exec-based ping.
type errICMPUnavailable struct{ err error }

func (e *errICMPUnavailable) Error() string { return e.err.Error() }

// pingDevice pings an IP address and returns the response time in milliseconds.
// Tries raw ICMP first for efficiency, falls back to exec-based ping only
// if the system doesn't support unprivileged ICMP.
func pingDevice(ip string, timeoutMs int) (float64, error) {
	ms, err := icmpPing(ip, timeoutMs)
	if err == nil {
		return ms, nil
	}

	// Only fall back to exec if ICMP sockets aren't available
	if _, ok := err.(*errICMPUnavailable); ok {
		return execPing(ip, timeoutMs)
	}
	return 0, err
}

// execPing uses the system ping command as a fallback.
func execPing(ip string, timeoutMs int) (float64, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	pingCmd := "ping"
	if parsedIP.To4() == nil {
		pingCmd = "ping6"
	}

	timeoutSecs := max(1, timeoutMs/1000)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs+1000)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, pingCmd, "-c", "1", "-W", strconv.Itoa(timeoutSecs), ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ping failed: %s", strings.TrimSpace(string(output)))
	}

	return parsePingTime(string(output))
}

// parsePingTime extracts the response time from ping output.
func parsePingTime(output string) (float64, error) {
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "time=")
		if idx < 0 {
			continue
		}
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
	return 0, fmt.Errorf("no time= field in ping output")
}
