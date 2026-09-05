// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

var (
	defaultHTTPTransport  = newCheckHTTPTransport(false)
	insecureHTTPTransport = newCheckHTTPTransport(true)
	sslRootCAsMu          sync.Mutex
	sslRootCAsPool        *x509.CertPool

	httpRegexCacheMu    sync.Mutex
	httpRegexCache      = make(map[string]*regexp.Regexp)
	httpRegexCacheOrder []string

	// systemCertPool loads the platform root store. Overridable for tests.
	systemCertPool = x509.SystemCertPool

	// tcpDialContext establishes the plain TCP connection used by TCP checks.
	// Overridable for tests.
	tcpDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	// dnsLookupTXT resolves TXT records for DNS checks. Overridable for tests.
	dnsLookupTXT = (*net.Resolver).LookupTXT

	// sslDialTLS establishes the TLS connection used by SSL checks.
	// Overridable for tests.
	sslDialTLS = func(ctx context.Context, dialer *net.Dialer, cfg *tls.Config, network, address string) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, network, address)
	}

	// sslRootCAs returns the system cert pool, cached after first successful load.
	// Errors are not cached — subsequent calls will retry loading.
	// Overridable for tests.
	sslRootCAs = func() (*x509.CertPool, error) {
		sslRootCAsMu.Lock()
		defer sslRootCAsMu.Unlock()
		if sslRootCAsPool != nil {
			return sslRootCAsPool, nil
		}
		pool, err := systemCertPool()
		if err != nil {
			return nil, err
		}
		sslRootCAsPool = pool
		return pool, nil
	}
)

// Check exit statuses, matching the Nagios convention the server stores.
const (
	checkOK       uint32 = 0
	checkWarning  uint32 = 1
	checkCritical uint32 = 2
	checkUnknown  uint32 = 3
)

const (
	maxHTTPRegexBody         = 1 << 20
	maxHTTPRegexCacheEntries = 64
	maxTCPOutputBytes        = 256
)

func newCheckHTTPTransport(insecure bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 10
	transport.IdleConnTimeout = 90 * time.Second
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport
}

// ExecuteCheck runs a service check and returns the result.
// Agent is stateless - just executes what it's told and reports back.
func ExecuteCheck(ctx context.Context, check *pb.Check) *pb.CheckResult {
	startTime := time.Now()

	var status uint32
	var output string

	switch check.CheckType {
	case "http":
		if httpConfig := check.GetHttp(); httpConfig != nil {
			status, output = executeHTTPCheck(ctx, httpConfig, check.TimeoutMs)
		} else {
			status, output = checkUnknown, "Missing HTTP config"
		}

	case "tcp":
		if tcpConfig := check.GetTcp(); tcpConfig != nil {
			status, output = executeTCPCheck(ctx, tcpConfig, check.TimeoutMs)
		} else {
			status, output = checkUnknown, "Missing TCP config"
		}

	case "dns":
		if dnsConfig := check.GetDns(); dnsConfig != nil {
			status, output = executeDNSCheck(ctx, dnsConfig, check.TimeoutMs)
		} else {
			status, output = checkUnknown, "Missing DNS config"
		}

	case "ssl":
		if sslConfig := check.GetSsl(); sslConfig != nil {
			status, output = executeSSLCheck(ctx, sslConfig, check.TimeoutMs)
		} else {
			status, output = checkUnknown, "Missing SSL config"
		}

	default:
		status, output = checkUnknown, fmt.Sprintf("Unknown check type: %s", check.CheckType)
	}

	// Always calculate elapsed from the outer startTime for consistency.
	responseTimeMs := float64(time.Since(startTime).Milliseconds())

	return &pb.CheckResult{
		CheckId:        check.Id,
		Status:         status,
		Output:         output,
		ResponseTimeMs: responseTimeMs,
		Timestamp:      time.Now().Unix(),
	}
}

// checkTimeout resolves a server-supplied per-check timeout, falling back to
// 10s when the server leaves it unset.
func checkTimeout(timeoutMs uint32) time.Duration {
	if timeoutMs == 0 {
		return 10 * time.Second
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

// executeHTTPCheck performs an HTTP/HTTPS check
func executeHTTPCheck(ctx context.Context, config *pb.HttpCheckConfig, timeoutMs uint32) (uint32, string) { // The server always sends verify_ssl explicitly: true unless the operator
	// opts out. A false zero value only skips verification for callers that
	// bypass the server's check builder.
	transport := defaultHTTPTransport
	if !config.VerifySsl {
		transport = insecureHTTPTransport
	}

	timeout := checkTimeout(timeoutMs)

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
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
		return checkCritical, fmt.Sprintf("Failed to create request: %v", err)
	}

	// Add headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return checkCritical, fmt.Sprintf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	expectedStatus := int(config.ExpectedStatus)
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	if resp.StatusCode != expectedStatus {
		// Drain the response before returning so repeated failing checks can
		// still reuse the shared transport connection.
		_, _ = io.Copy(io.Discard, resp.Body)
		return checkCritical, fmt.Sprintf("HTTP %d, expected %d", resp.StatusCode, expectedStatus)
	}

	// Check content regex if provided
	if config.Regex != "" {
		re, err := cachedHTTPRegex(config.Regex)
		if err != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			return checkUnknown, fmt.Sprintf("Invalid regex: %v", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPRegexBody+1))
		if err != nil {
			return checkCritical, fmt.Sprintf("Failed to read body: %v", err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return checkCritical, fmt.Sprintf("Failed to read body: %v", err)
		}
		if len(body) > maxHTTPRegexBody {
			return checkUnknown, fmt.Sprintf("Response body exceeds regex limit of %d bytes", maxHTTPRegexBody)
		}

		if !re.Match(body) {
			return checkCritical, fmt.Sprintf("Content does not match pattern: %s", config.Regex)
		}
	} else {
		// Consume successful response bodies so the shared transport can reuse
		// the underlying connection for subsequent checks.
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return checkCritical, fmt.Sprintf("Failed to read body: %v", err)
		}
	}

	return checkOK, fmt.Sprintf("HTTP %d OK", resp.StatusCode)
}

// cachedHTTPRegex uses a small FIFO cache: regexes are reused across frequent
// checks while the fixed capacity prevents server-supplied patterns from
// growing agent memory without bound. Invalid patterns are never cached.
func cachedHTTPRegex(pattern string) (*regexp.Regexp, error) {
	httpRegexCacheMu.Lock()
	defer httpRegexCacheMu.Unlock()

	if re, ok := httpRegexCache[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	if len(httpRegexCacheOrder) == maxHTTPRegexCacheEntries {
		evicted := httpRegexCacheOrder[0]
		delete(httpRegexCache, evicted)
		httpRegexCacheOrder = httpRegexCacheOrder[1:]
	}
	httpRegexCache[pattern] = re
	httpRegexCacheOrder = append(httpRegexCacheOrder, pattern)
	return re, nil
}

// executeTCPCheck performs a TCP port connectivity check
func executeTCPCheck(ctx context.Context, config *pb.TcpCheckConfig, timeoutMs uint32) (uint32, string) {
	timeout := checkTimeout(timeoutMs)
	address := net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port)))

	startTime := time.Now()
	deadline := startTime.Add(timeout)
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()
	conn, err := tcpDialContext(dialCtx, "tcp", address)
	if err != nil {
		return checkCritical, fmt.Sprintf("Connection failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// If send/expect strings are provided, keep both operations within the
	// original end-to-end timeout budget.
	if config.Send != "" || config.Expect != "" {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return checkCritical, fmt.Sprintf("Set deadline failed: %v", err)
		}

		if config.Send != "" {
			if err := writeAll(conn, []byte(config.Send)); err != nil {
				return checkCritical, fmt.Sprintf("Send failed: %v", err)
			}
		}

		if config.Expect != "" {
			const maxTCPResponse = 64 << 10
			want := []byte(config.Expect)
			received := make([]byte, 0, 4096)
			buffer := make([]byte, 4096)
			for len(received) < maxTCPResponse {
				n, readErr := conn.Read(buffer)
				received = append(received, buffer[:n]...)
				if bytes.Contains(received, want) {
					break
				}
				if readErr != nil {
					if len(received) > 0 {
						return checkCritical, fmt.Sprintf("Unexpected response: %s", tcpResponseForOutput(received))
					}
					return checkCritical, fmt.Sprintf("Receive failed: %v", readErr)
				}
			}
			if !bytes.Contains(received, want) {
				return checkCritical, fmt.Sprintf("Unexpected response: %s", tcpResponseForOutput(received))
			}
		}
	}

	return checkOK, fmt.Sprintf("TCP port %d open", config.Port)
}

func tcpResponseForOutput(response []byte) string {
	totalBytes := len(response)
	truncated := totalBytes > maxTCPOutputBytes
	if truncated {
		response = response[:maxTCPOutputBytes]
	}

	var output strings.Builder
	output.Grow(len(response) + 48)
	for _, b := range response {
		if b >= 0x20 && b <= 0x7e {
			output.WriteByte(b)
		} else {
			output.WriteByte('.')
		}
	}
	if truncated {
		output.WriteString(" [truncated; ")
		output.WriteString(strconv.Itoa(totalBytes))
		output.WriteString(" bytes received]")
	}
	return output.String()
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// executeDNSCheck performs a DNS resolution check
func executeDNSCheck(ctx context.Context, config *pb.DnsCheckConfig, timeoutMs uint32) (uint32, string) {
	timeout := checkTimeout(timeoutMs)

	resolver := &net.Resolver{}
	if config.Server != "" {
		resolver = resolverForServer(config.Server, timeout)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	recordType := strings.ToUpper(config.RecordType)
	if recordType == "" {
		recordType = "A"
	}

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
		txts, lookupErr := dnsLookupTXT(resolver, ctx, config.Hostname)
		err = lookupErr
		results = txts

	default:
		return checkUnknown, fmt.Sprintf("Unsupported record type: %s", recordType)
	}

	if err != nil {
		return checkCritical, fmt.Sprintf("DNS query failed: %v", err)
	}

	if len(results) == 0 {
		return checkCritical, fmt.Sprintf("No %s records found", recordType)
	}

	// Check expected result if provided
	if config.Expected != "" && !dnsAnswerMatches(recordType, results, config.Expected) {
		return checkCritical, fmt.Sprintf("Expected '%s', got: %s", config.Expected, strings.Join(results, ", "))
	}

	return checkOK, fmt.Sprintf("Resolved to: %s", strings.Join(results, ", "))
}

// dnsAnswerMatches reports whether any answer is the one the operator expects.
// Go returns CNAME and MX names as FQDNs with a trailing dot, so comparing
// them verbatim made "example.com" a permanent CRITICAL. An MX answer is
// formatted "<pref> <host>" and matches either that whole string or the host
// on its own, which is how operators usually write it.
//
// Only those two record types hold hostnames. A, AAAA and TXT answers are
// compared exactly: a trailing dot is part of a TXT value, not name syntax.
func dnsAnswerMatches(recordType string, results []string, expected string) bool {
	if recordType != "CNAME" && recordType != "MX" {
		return slices.Contains(results, expected)
	}

	want := strings.TrimSuffix(expected, ".")
	for _, result := range results {
		if strings.TrimSuffix(result, ".") == want {
			return true
		}
		if recordType == "MX" {
			if _, host, found := strings.Cut(result, " "); found && strings.TrimSuffix(host, ".") == want {
				return true
			}
		}
	}
	return false
}

func resolverForServer(server string, timeout time.Duration) *net.Resolver {
	address := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		address = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, address)
		},
	}
}

// executeSSLCheck connects via TLS and applies the certificate status policy.
// Operational failures before a certificate can be evaluated, including root
// store, connection, handshake, non-TLS, and no-certificate failures, are
// UNKNOWN. Expired, not-yet-valid, untrusted, and hostname-mismatched
// certificates are CRITICAL. A trusted certificate inside warning_days is
// WARNING; every other trusted certificate is OK.
func executeSSLCheck(ctx context.Context, config *pb.SslCheckConfig, timeoutMs uint32) (uint32, string) {
	timeout := checkTimeout(timeoutMs)

	host := config.Host
	port := config.Port
	if port == 0 {
		port = 443
	}
	warningDays := config.WarningDays
	if warningDays == 0 {
		warningDays = 30
	}

	address := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dialer := &net.Dialer{Timeout: timeout}
	rootCAs, err := sslRootCAs()
	if err != nil {
		return checkUnknown, fmt.Sprintf("Failed to load system root CAs: %v", err)
	}
	// Standard verification is deferred so invalid certificates remain
	// available for the status policy below.
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := sslDialTLS(dialCtx, dialer, tlsConfig, "tcp", address)
	if err != nil {
		return checkUnknown, fmt.Sprintf("Connection failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return checkUnknown, "Connection did not negotiate TLS"
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return checkUnknown, fmt.Sprintf("No certificate presented by %s:%d", host, port)
	}

	now := time.Now()
	cert := certs[0]
	notAfter := cert.NotAfter
	daysRemaining, expired := certificateDaysRemaining(now, notAfter)
	expiresStr := notAfter.Format("2006-01-02")

	if now.Before(cert.NotBefore) {
		return checkCritical, fmt.Sprintf("CRITICAL: Certificate for %s:%d is not valid until %s", host, port, cert.NotBefore.Format("2006-01-02"))
	}
	if expired {
		return checkCritical, fmt.Sprintf("CRITICAL: Certificate for %s:%d expired %d days ago (%s)", host, port, -daysRemaining, expiresStr)
	}

	intermediates := x509.NewCertPool()
	for _, intermediate := range certs[1:] {
		intermediates.AddCert(intermediate)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		DNSName:       host,
		CurrentTime:   now,
	}); err != nil {
		return checkCritical, fmt.Sprintf("CRITICAL: Certificate for %s:%d is not trusted: %v", host, port, err)
	}

	if daysRemaining <= int(warningDays) {
		return checkWarning, fmt.Sprintf("WARNING: Certificate for %s:%d expires in %d days (%s)", host, port, daysRemaining, expiresStr)
	}
	return checkOK, fmt.Sprintf("OK: Certificate for %s:%d valid for %d days (%s)", host, port, daysRemaining, expiresStr)
}

func certificateDaysRemaining(now, notAfter time.Time) (days int, expired bool) {
	days = int(notAfter.Sub(now).Hours() / 24)
	return days, !notAfter.After(now)
}
