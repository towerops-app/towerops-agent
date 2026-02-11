package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// pingDevice pings an IP address and returns the response time in milliseconds.
func pingDevice(ip string, timeoutMs int) (float64, error) {
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
