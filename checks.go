package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.mcintire.me/towerops-agent/towerops-agent/pb"
)

var (
	defaultHTTPTransport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	insecureHTTPTransport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	sslRootCAsMu   sync.Mutex
	sslRootCAsPool *x509.CertPool

	// sslRootCAs returns the system cert pool, cached after first successful load.
	// Errors are not cached — subsequent calls will retry loading.
	// Overridable for tests.
	sslRootCAs = func() (*x509.CertPool, error) {
		sslRootCAsMu.Lock()
		defer sslRootCAsMu.Unlock()
		if sslRootCAsPool != nil {
			return sslRootCAsPool, nil
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		sslRootCAsPool = pool
		return pool, nil
	}
)

// ExecuteCheck runs a service check and returns the result.
// Agent is stateless - just executes what it's told and reports back.
func ExecuteCheck(ctx context.Context, check *pb.Check) *pb.CheckResult {
	startTime := time.Now()

	var status uint32
	var output string

	switch check.CheckType {
	case "http":
		if httpConfig := check.GetHttp(); httpConfig != nil {
			status, output, _ = executeHTTPCheck(ctx, httpConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing HTTP config"
		}

	case "tcp":
		if tcpConfig := check.GetTcp(); tcpConfig != nil {
			status, output, _ = executeTCPCheck(ctx, tcpConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing TCP config"
		}

	case "dns":
		if dnsConfig := check.GetDns(); dnsConfig != nil {
			status, output, _ = executeDNSCheck(ctx, dnsConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing DNS config"
		}

	case "ssl":
		if sslConfig := check.GetSsl(); sslConfig != nil {
			status, output, _ = executeSSLCheck(ctx, sslConfig, check.TimeoutMs)
		} else {
			status, output = 3, "Missing SSL config"
		}

	default:
		status, output = 3, fmt.Sprintf("Unknown check type: %s", check.CheckType)
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

// executeHTTPCheck performs an HTTP/HTTPS check
func executeHTTPCheck(ctx context.Context, config *pb.HttpCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	transport := defaultHTTPTransport
	if !config.VerifySsl {
		transport = insecureHTTPTransport
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}

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
		// Drain the response before returning so repeated failing checks can
		// still reuse the shared transport connection.
		_, _ = io.Copy(io.Discard, resp.Body)
		return 2, fmt.Sprintf("HTTP %d, expected %d", resp.StatusCode, expectedStatus), responseTime
	}

	// Check content regex if provided
	if config.Regex != "" {
		re, err := regexp.Compile(config.Regex)
		if err != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			return 3, fmt.Sprintf("Invalid regex: %v", err), responseTime
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return 2, fmt.Sprintf("Failed to read body: %v", err), responseTime
		}

		if !re.Match(body) {
			return 2, fmt.Sprintf("Content does not match pattern: %s", config.Regex), responseTime
		}
	} else {
		// Consume successful response bodies so the shared transport can reuse
		// the underlying connection for subsequent checks.
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return 2, fmt.Sprintf("Failed to read body: %v", err), responseTime
		}
	}

	return 0, fmt.Sprintf("HTTP %d OK", resp.StatusCode), responseTime
}

// executeTCPCheck performs a TCP port connectivity check
func executeTCPCheck(ctx context.Context, config *pb.TcpCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	if timeoutMs == 0 {
		timeoutMs = 10000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	address := net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port)))

	startTime := time.Now()
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", address)
	responseTime := float64(time.Since(startTime).Milliseconds())

	if err != nil {
		return 2, fmt.Sprintf("Connection failed: %v", err), responseTime
	}
	defer func() { _ = conn.Close() }()

	// If send/expect strings provided, test them
	if config.Send != "" {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			return 2, fmt.Sprintf("Set deadline failed: %v", err), responseTime
		}

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
	if timeoutMs == 0 {
		timeoutMs = 10000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	resolver := &net.Resolver{}
	if config.Server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", net.JoinHostPort(config.Server, "53"))
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

// executeSSLCheck connects via TLS and checks the certificate expiration date.
func executeSSLCheck(ctx context.Context, config *pb.SslCheckConfig, timeoutMs uint32) (uint32, string, float64) {
	if timeoutMs == 0 {
		timeoutMs = 10000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

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
		return 3, fmt.Sprintf("Failed to load system root CAs: %v", err), 0
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: host,
	}

	startTime := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&tls.Dialer{
		NetDialer: dialer,
		Config:    tlsConfig,
	}).DialContext(dialCtx, "tcp", address)
	responseTime := float64(time.Since(startTime).Milliseconds())

	if err != nil {
		return 3, fmt.Sprintf("Connection failed: %v", err), responseTime
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return 3, "Connection did not negotiate TLS", responseTime
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return 3, fmt.Sprintf("No certificate presented by %s:%d", host, port), responseTime
	}

	cert := certs[0]
	notAfter := cert.NotAfter
	daysRemaining := int(time.Until(notAfter).Hours() / 24)
	expiresStr := notAfter.Format("2006-01-02")

	switch {
	case daysRemaining < 0:
		return 2, fmt.Sprintf("CRITICAL: Certificate for %s:%d expired %d days ago (%s)", host, port, -daysRemaining, expiresStr), responseTime
	case daysRemaining <= int(warningDays):
		return 1, fmt.Sprintf("WARNING: Certificate for %s:%d expires in %d days (%s)", host, port, daysRemaining, expiresStr), responseTime
	default:
		return 0, fmt.Sprintf("OK: Certificate for %s:%d valid for %d days (%s)", host, port, daysRemaining, expiresStr), responseTime
	}
}
