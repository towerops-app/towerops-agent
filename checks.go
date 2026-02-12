package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// ExecuteCheck runs a service check and returns the result.
// Agent is stateless - just executes what it's told and reports back.
func ExecuteCheck(ctx context.Context, check *pb.Check) *pb.CheckResult {
	startTime := time.Now()

	var status uint32
	var output string
	var responseTimeMs float64

	switch check.CheckType {
	case "http":
		if httpConfig := check.GetHttp(); httpConfig != nil {
			status, output, responseTimeMs = executeHTTPCheck(ctx, httpConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing HTTP config"
		}

	case "tcp":
		if tcpConfig := check.GetTcp(); tcpConfig != nil {
			status, output, responseTimeMs = executeTCPCheck(ctx, tcpConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing TCP config"
		}

	case "dns":
		if dnsConfig := check.GetDns(); dnsConfig != nil {
			status, output, responseTimeMs = executeDNSCheck(ctx, dnsConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing DNS config"
		}

	default:
		status, output = 3, fmt.Sprintf("Unknown check type: %s", check.CheckType)
	}

	// If responseTimeMs wasn't set by executor, calculate from start time
	if responseTimeMs == 0 {
		responseTimeMs = float64(time.Since(startTime).Milliseconds())
	}

	return &pb.CheckResult{
		CheckId:        check.Id,
		Status:         status,
		Output:         output,
		ResponseTimeMs: responseTimeMs,
		Timestamp:      time.Now().Unix(),
	}
}

// executeHTTPCheck performs an HTTP/HTTPS check
func executeHTTPCheck(ctx context.Context, config *pb.HttpCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Create HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.VerifySsl,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	method := strings.ToUpper(config.Method)
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, config.Url, strings.NewReader(config.Body))
	if err != nil {
		return 2, fmt.Sprintf("Failed to create request: %v", err), 0
	}

	// Add headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := float64(time.Since(startTime).Milliseconds())

	if err != nil {
		return 2, fmt.Sprintf("Request failed: %v", err), responseTime
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	expectedStatus := int(config.ExpectedStatus)
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	if resp.StatusCode != expectedStatus {
		return 2, fmt.Sprintf("HTTP %d, expected %d", resp.StatusCode, expectedStatus), responseTime
	}

	// Check content regex if provided
	if config.Regex != "" {
		body := make([]byte, 1024*1024) // Read up to 1MB
		n, _ := resp.Body.Read(body)

		matched, err := regexp.MatchString(config.Regex, string(body[:n]))
		if err != nil {
			return 2, fmt.Sprintf("Invalid regex: %v", err), responseTime
		}

		if !matched {
			return 2, fmt.Sprintf("Content does not match pattern: %s", config.Regex), responseTime
		}
	}

	return 0, fmt.Sprintf("HTTP %d OK", resp.StatusCode), responseTime
}

// executeTCPCheck performs a TCP port connectivity check
func executeTCPCheck(ctx context.Context, config *pb.TcpCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	address := net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port)))

	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	responseTime := float64(time.Since(startTime).Milliseconds())

	if err != nil {
		return 2, fmt.Sprintf("Connection failed: %v", err), responseTime
	}
	defer func() { _ = conn.Close() }()

	// If send/expect strings provided, test them
	if config.Send != "" {
		_ = conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write([]byte(config.Send))
		if err != nil {
			return 2, fmt.Sprintf("Send failed: %v", err), responseTime
		}

		if config.Expect != "" {
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				return 2, fmt.Sprintf("Receive failed: %v", err), responseTime
			}

			received := string(buffer[:n])
			if !strings.Contains(received, config.Expect) {
				return 2, fmt.Sprintf("Unexpected response: %s", received), responseTime
			}
		}
	}

	return 0, fmt.Sprintf("TCP port %d open", config.Port), responseTime
}

// executeDNSCheck performs a DNS resolution check
func executeDNSCheck(ctx context.Context, config *pb.DnsCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	timeout := time.Duration(timeoutMs) * time.Millisecond

	resolver := &net.Resolver{}
	if config.Server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", config.Server+":53")
			},
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	recordType := strings.ToUpper(config.RecordType)
	if recordType == "" {
		recordType = "A"
	}

	startTime := time.Now()

	var results []string
	var err error

	switch recordType {
	case "A":
		ips, lookupErr := resolver.LookupIP(ctx, "ip4", config.Hostname)
		err = lookupErr
		for _, ip := range ips {
			results = append(results, ip.String())
		}

	case "AAAA":
		ips, lookupErr := resolver.LookupIP(ctx, "ip6", config.Hostname)
		err = lookupErr
		for _, ip := range ips {
			results = append(results, ip.String())
		}

	case "CNAME":
		cname, lookupErr := resolver.LookupCNAME(ctx, config.Hostname)
		err = lookupErr
		if cname != "" {
			results = append(results, cname)
		}

	case "MX":
		mxs, lookupErr := resolver.LookupMX(ctx, config.Hostname)
		err = lookupErr
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}

	case "TXT":
		txts, lookupErr := resolver.LookupTXT(ctx, config.Hostname)
		err = lookupErr
		results = txts

	default:
		return 3, fmt.Sprintf("Unsupported record type: %s", recordType), 0
	}

	responseTime := float64(time.Since(startTime).Milliseconds())

	if err != nil {
		return 2, fmt.Sprintf("DNS query failed: %v", err), responseTime
	}

	if len(results) == 0 {
		return 2, fmt.Sprintf("No %s records found", recordType), responseTime
	}

	// Check expected result if provided
	if config.Expected != "" {
		found := false
		for _, result := range results {
			if result == config.Expected {
				found = true
				break
			}
		}

		if !found {
			return 2, fmt.Sprintf("Expected '%s', got: %s", config.Expected, strings.Join(results, ", ")), responseTime
		}
	}

	return 0, fmt.Sprintf("Resolved to: %s", strings.Join(results, ", ")), responseTime
}
