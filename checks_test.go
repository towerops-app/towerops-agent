package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

// ---------------------------------------------------------------------------
// ExecuteCheck routing tests
// ---------------------------------------------------------------------------

func TestExecuteCheck_UnknownCheckType(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-1",
		CheckType: "foobar",
		TimeoutMs: 5000,
	})
	if result.Status != 3 {
		t.Fatalf("expected status 3, got %d", result.Status)
	}
	if result.CheckId != "chk-1" {
		t.Fatalf("expected CheckId chk-1, got %s", result.CheckId)
	}
	if !strings.Contains(result.Output, "Unknown check type") {
		t.Fatalf("expected unknown check type message, got %s", result.Output)
	}
}

func TestExecuteCheck_MissingHTTPConfig(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-2",
		CheckType: "http",
		TimeoutMs: 5000,
		// No Config set
	})
	if result.Status != 3 {
		t.Fatalf("expected status 3, got %d", result.Status)
	}
	if !strings.Contains(result.Output, "Missing HTTP config") {
		t.Fatalf("expected missing HTTP config message, got %s", result.Output)
	}
}

func TestExecuteCheck_MissingTCPConfig(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-3",
		CheckType: "tcp",
		TimeoutMs: 5000,
	})
	if result.Status != 3 {
		t.Fatalf("expected status 3, got %d", result.Status)
	}
	if !strings.Contains(result.Output, "Missing TCP config") {
		t.Fatalf("expected missing TCP config message, got %s", result.Output)
	}
}

func TestExecuteCheck_MissingDNSConfig(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-4",
		CheckType: "dns",
		TimeoutMs: 5000,
	})
	if result.Status != 3 {
		t.Fatalf("expected status 3, got %d", result.Status)
	}
	if !strings.Contains(result.Output, "Missing DNS config") {
		t.Fatalf("expected missing DNS config message, got %s", result.Output)
	}
}

func TestExecuteCheck_SetsCheckIdAndTimestamp(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-ts",
		CheckType: "unknown",
		TimeoutMs: 5000,
	})
	if result.CheckId != "chk-ts" {
		t.Fatalf("expected CheckId chk-ts, got %s", result.CheckId)
	}
	if result.Timestamp == 0 {
		t.Fatal("expected non-zero timestamp")
	}
	if result.ResponseTimeMs < 0 {
		t.Fatalf("expected non-negative response time, got %f", result.ResponseTimeMs)
	}
}

func TestExecuteCheck_HTTPRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-route-http",
		CheckType: "http",
		TimeoutMs: 5000,
		Config: &pb.Check_Http{
			Http: &pb.HttpCheckConfig{
				Url: srv.URL,
			},
		},
	})
	if result.Status != 0 {
		t.Fatalf("expected status 0, got %d: %s", result.Status, result.Output)
	}
}

func TestExecuteCheck_TCPRouting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-route-tcp",
		CheckType: "tcp",
		TimeoutMs: 5000,
		Config: &pb.Check_Tcp{
			Tcp: &pb.TcpCheckConfig{
				Host: "127.0.0.1",
				Port: parsePort(portStr),
			},
		},
	})
	if result.Status != 0 {
		t.Fatalf("expected status 0, got %d: %s", result.Status, result.Output)
	}
}

func TestExecuteCheck_DNSRouting(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-route-dns",
		CheckType: "dns",
		TimeoutMs: 5000,
		Config: &pb.Check_Dns{
			Dns: &pb.DnsCheckConfig{
				Hostname:   "localhost",
				RecordType: "A",
			},
		},
	})
	// DNS for localhost may or may not resolve depending on system config,
	// but the routing should work regardless.
	if result.Status == 3 {
		t.Fatalf("expected routing to DNS handler, got status 3 (UNKNOWN): %s", result.Output)
	}
}

// ---------------------------------------------------------------------------
// HTTP check tests
// ---------------------------------------------------------------------------

func TestHTTPCheck_SuccessfulGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	status, output, rt := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, "HTTP 200 OK") {
		t.Fatalf("expected HTTP 200 OK in output, got %s", output)
	}
	if rt < 0 {
		t.Fatalf("expected non-negative response time, got %f", rt)
	}
}

func TestHTTPCheck_CustomMethod_POST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "post",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_CustomExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:            srv.URL,
		ExpectedStatus: 201,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_WrongStatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
	if !strings.Contains(output, "500") && !strings.Contains(output, "expected 200") {
		t.Fatalf("expected status code mismatch message, got %s", output)
	}
}

func TestHTTPCheck_DefaultMethodIsGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected default GET, got %s", r.Method)
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "", // should default to GET
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_DefaultExpectedStatusIs200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:            srv.URL,
		ExpectedStatus: 0, // should default to 200
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_VerifySslFalseWithSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// With VerifySsl=false (InsecureSkipVerify=true), the self-signed cert should be accepted
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       srv.URL,
		VerifySsl: false,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 with VerifySsl=false, got %d: %s", status, output)
	}
}

func TestHTTPCheck_VerifySslTrueRejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// With VerifySsl=true (InsecureSkipVerify=false), self-signed cert should fail
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       srv.URL,
		VerifySsl: true,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 with VerifySsl=true on self-signed, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Request failed") {
		t.Fatalf("expected request failed message, got %s", output)
	}
}

func TestHTTPCheck_FollowRedirectsTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "final page")
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:             srv.URL + "/redirect",
		FollowRedirects: true,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 after following redirect, got %d: %s", status, output)
	}
	if !strings.Contains(output, "200") {
		t.Fatalf("expected final 200 status in output, got %s", output)
	}
}

func TestHTTPCheck_FollowRedirectsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// When FollowRedirects is false, we should see the 301 directly
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:             srv.URL + "/redirect",
		FollowRedirects: false,
		ExpectedStatus:  301,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 (matching 301), got %d: %s", status, output)
	}
}

func TestHTTPCheck_FollowRedirectsFalse_DefaultExpects200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	// FollowRedirects=false and default expected=200, but we get 301 → CRITICAL
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:             srv.URL + "/redirect",
		FollowRedirects: false,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 (301 != 200), got %d: %s", status, output)
	}
}

func TestHTTPCheck_RegexMatchSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "Hello World! Version 1.2.3")
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `Version \d+\.\d+\.\d+`,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 for regex match, got %d: %s", status, output)
	}
}

func TestHTTPCheck_RegexMatchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "Hello World!")
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `Version \d+`,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for regex mismatch, got %d: %s", status, output)
	}
	if !strings.Contains(output, "does not match") {
		t.Fatalf("expected 'does not match' in output, got %s", output)
	}
}

func TestHTTPCheck_InvalidRegex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "some body")
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `[invalid`,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for invalid regex, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Invalid regex") {
		t.Fatalf("expected 'Invalid regex' in output, got %s", output)
	}
}

func TestHTTPCheck_CustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("expected X-Custom header to be test-value, got %s", r.Header.Get("X-Custom"))
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Authorization") != "Bearer abc123" {
			t.Errorf("expected Authorization header, got %s", r.Header.Get("Authorization"))
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
		Headers: map[string]string{
			"X-Custom":      "test-value",
			"Authorization": "Bearer abc123",
		},
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_UnreachableServer(t *testing.T) {
	// Use a non-routable address to guarantee failure
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: "http://192.0.2.1:1/unreachable",
	}, 1000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Request failed") {
		t.Fatalf("expected 'Request failed' in output, got %s", output)
	}
}

func TestHTTPCheck_InvalidURL(t *testing.T) {
	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: "://not-a-url",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Failed to create request") {
		t.Fatalf("expected 'Failed to create request' in output, got %s", output)
	}
}

func TestHTTPCheck_RequestWithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		if body != `{"key":"value"}` {
			t.Errorf("expected JSON body, got %s", body)
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "POST",
		Body:   `{"key":"value"}`,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_ContextCancellation(t *testing.T) {
	// Server that hangs forever
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	status, output, _ := executeHTTPCheck(ctx, &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 30000) // long timeout so the context cancel hits first

	if status != 2 {
		t.Fatalf("expected status 2 on context cancel, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Request failed") {
		t.Fatalf("expected 'Request failed' in output, got %s", output)
	}
}

func TestHTTPCheck_LargeResponseBodyWithRegex(t *testing.T) {
	// Generate a large body (500KB) with a marker at the end
	bigBody := strings.Repeat("a", 500*1024) + "MARKER_FOUND_HERE"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, bigBody)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `MARKER_FOUND_HERE`,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 for regex match in large body, got %d: %s", status, output)
	}
}

func TestHTTPCheck_SlowServerTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 50) // 50ms timeout, server takes 500ms

	if status != 2 {
		t.Fatalf("expected status 2 for timeout, got %d: %s", status, output)
	}
}

func TestHTTPCheck_EmptyBody_NoRegex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

// ---------------------------------------------------------------------------
// TCP check tests
// ---------------------------------------------------------------------------

func TestTCPCheck_PortOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Accept connections in background so dial doesn't hang
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, rt := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, fmt.Sprintf("TCP port %d open", port)) {
		t.Fatalf("expected port open message, got %s", output)
	}
	if rt < 0 {
		t.Fatalf("expected non-negative response time, got %f", rt)
	}
}

func TestTCPCheck_PortClosed(t *testing.T) {
	// Find a port that's definitely not listening by binding and immediately closing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := parsePort(portFromListener(ln))
	_ = ln.Close() // close immediately so port is refused

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 2000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Connection failed") {
		t.Fatalf("expected 'Connection failed' in output, got %s", output)
	}
}

func TestTCPCheck_SendExpectSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Echo server
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				scanner := bufio.NewScanner(c)
				if scanner.Scan() {
					line := scanner.Text()
					_, _ = fmt.Fprintf(c, "ECHO:%s\n", line)
				}
			}(conn)
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   "hello\n",
		Expect: "ECHO:hello",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestTCPCheck_SendExpectMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = fmt.Fprint(c, "WRONG_RESPONSE")
			}(conn)
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   "hello",
		Expect: "EXPECTED_VALUE",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Unexpected response") {
		t.Fatalf("expected 'Unexpected response' in output, got %s", output)
	}
}

func TestTCPCheck_SendWithEmptyExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				// Don't send anything back
			}(conn)
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   "data\n",
		Expect: "", // no expect check
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 (send only, no expect), got %d: %s", status, output)
	}
}

func TestTCPCheck_IPv6Localhost(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available on this system")
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "::1",
		Port: port,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 for IPv6, got %d: %s", status, output)
	}
}

func TestTCPCheck_ReadTimeoutOnExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Server that accepts and reads but never writes back
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				// Intentionally never respond - hold connection open
				time.Sleep(10 * time.Second)
			}(conn)
		}
	}()

	port := parsePort(portFromListener(ln))

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   "hello",
		Expect: "response",
	}, 200) // short timeout

	if status != 2 {
		t.Fatalf("expected status 2 for read timeout, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Receive failed") {
		t.Fatalf("expected 'Receive failed' in output, got %s", output)
	}
}

func TestTCPCheck_VeryShortTimeout(t *testing.T) {
	// Use TEST-NET address that won't respond
	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "192.0.2.1",
		Port: 80,
	}, 1) // 1ms timeout - should fail

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
}

func TestTCPCheck_BinaryDataSendExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Server that echoes binary data back
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	port := parsePort(portFromListener(ln))

	// Send some binary-ish data
	sendData := "BIN\x00\x01\x02DATA"
	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   sendData,
		Expect: sendData,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 for binary echo, got %d: %s", status, output)
	}
}

// ---------------------------------------------------------------------------
// DNS check tests
// ---------------------------------------------------------------------------

func TestDNSCheck_ARecord(t *testing.T) {
	status, output, rt := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "A",
	}, 5000)

	// localhost should resolve on most systems, but skip if it doesn't
	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available for localhost")
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Resolved to:") {
		t.Fatalf("expected 'Resolved to:' in output, got %s", output)
	}
	if rt < 0 {
		t.Fatalf("expected non-negative response time, got %f", rt)
	}
}

func TestDNSCheck_AAAARecord(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "AAAA",
	}, 5000)

	// AAAA for localhost may or may not exist - just verify it doesn't crash
	// and returns a valid status
	if status != 0 && status != 2 {
		t.Fatalf("expected status 0 or 2, got %d: %s", status, output)
	}
}

func TestDNSCheck_CNAMERecord(t *testing.T) {
	// Use a well-known domain that has a CNAME
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "www.google.com",
		RecordType: "CNAME",
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available")
	}
	// CNAME lookup may return the hostname itself if no CNAME exists
	if status != 0 && status != 2 {
		t.Fatalf("expected status 0 or 2, got %d: %s", status, output)
	}
}

func TestDNSCheck_MXRecord(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "google.com",
		RecordType: "MX",
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available")
	}
	if status != 0 {
		t.Fatalf("expected status 0 for MX lookup, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Resolved to:") {
		t.Fatalf("expected 'Resolved to:' in output, got %s", output)
	}
}

func TestDNSCheck_TXTRecord(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "google.com",
		RecordType: "TXT",
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available")
	}
	if status != 0 {
		t.Fatalf("expected status 0 for TXT lookup, got %d: %s", status, output)
	}
}

func TestDNSCheck_UnsupportedRecordType(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "example.com",
		RecordType: "SRV",
	}, 5000)

	if status != 3 {
		t.Fatalf("expected status 3, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Unsupported record type") {
		t.Fatalf("expected 'Unsupported record type' in output, got %s", output)
	}
}

func TestDNSCheck_ExpectedMatchesResult(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "A",
		Expected:   "127.0.0.1",
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available for localhost")
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestDNSCheck_ExpectedDoesNotMatch(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "A",
		Expected:   "10.99.99.99",
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available for localhost")
	}
	// If localhost resolved, the expected won't match
	if status != 2 {
		t.Fatalf("expected status 2 for mismatched expected, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Expected '10.99.99.99'") {
		t.Fatalf("expected mismatch message, got %s", output)
	}
}

func TestDNSCheck_NonexistentDomain(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "this-domain-does-not-exist-towerops-test.invalid",
		RecordType: "A",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for NXDOMAIN, got %d: %s", status, output)
	}
}

func TestDNSCheck_DefaultRecordTypeIsA(t *testing.T) {
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "", // should default to A
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available for localhost")
	}
	// Should behave the same as explicitly specifying "A"
	if status != 0 {
		t.Fatalf("expected status 0 with default record type, got %d: %s", status, output)
	}
}

func TestDNSCheck_CustomDNSServer(t *testing.T) {
	// Test with Google's public DNS
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		t.Skip("Cannot reach 8.8.8.8:53, skipping custom DNS server test")
	}
	_ = conn.Close()

	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "example.com",
		RecordType: "A",
		Server:     "8.8.8.8",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 with custom DNS server, got %d: %s", status, output)
	}
}

func TestDNSCheck_RecordTypeCaseInsensitive(t *testing.T) {
	// The code does strings.ToUpper, so lowercase should work
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "localhost",
		RecordType: "a", // lowercase
	}, 5000)

	if status == 2 && strings.Contains(output, "DNS query failed") {
		t.Skip("DNS resolution not available for localhost")
	}
	if status != 0 {
		t.Fatalf("expected status 0 with lowercase record type, got %d: %s", status, output)
	}
}

func TestDNSCheck_NoRecordsFound(t *testing.T) {
	// AAAA for a domain that likely only has A records
	// Use a known domain that almost certainly won't have AAAA
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "this-domain-does-not-exist-towerops-test.invalid",
		RecordType: "AAAA",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
}

func TestDNSCheck_VeryShortTimeout(t *testing.T) {
	// Use a custom DNS server with 1ms timeout - should timeout
	status, output, _ := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "example.com",
		RecordType: "A",
		Server:     "8.8.8.8",
	}, 1) // 1ms timeout

	// Should fail due to timeout
	if status != 2 {
		// On very fast networks this could actually succeed, so just verify it doesn't crash
		t.Logf("DNS with 1ms timeout returned status %d: %s (may succeed on fast networks)", status, output)
	}
}

func TestTCPCheck_SendFailsOnClosedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Server accepts and immediately closes the connection
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := parsePort(portFromListener(ln))

	// Send a large payload to trigger a write error on a closed connection.
	// The first small write might succeed (kernel buffer), but a large write
	// after the peer has closed should fail with a broken pipe or similar.
	largePayload := strings.Repeat("x", 1024*1024) // 1MB
	// Give the server time to close the connection
	time.Sleep(50 * time.Millisecond)

	status, output, _ := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   largePayload,
		Expect: "something",
	}, 5000)

	// This may hit either "Send failed" or "Receive failed" depending on timing
	if status != 2 {
		t.Fatalf("expected status 2 for write to closed conn, got %d: %s", status, output)
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestHTTPCheck_MethodUppercased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "put", // lowercase
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_ResponseTimeIsPositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, _, rt := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 5000)

	if rt <= 0 {
		t.Fatalf("expected positive response time, got %f", rt)
	}
}

func TestTCPCheck_ResponseTimeReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := parsePort(portFromListener(ln))
	_, _, rt := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 5000)

	if rt < 0 {
		t.Fatalf("expected non-negative response time, got %f", rt)
	}
}

func TestExecuteCheck_ResponseTimeFallback(t *testing.T) {
	// When status/output are set directly (unknown type), responseTimeMs should be calculated
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-fallback",
		CheckType: "invalid",
		TimeoutMs: 5000,
	})

	if result.ResponseTimeMs < 0 {
		t.Fatalf("expected non-negative response time, got %f", result.ResponseTimeMs)
	}
}

func TestHTTPCheck_TLSServerNoVerify(t *testing.T) {
	// Create a TLS server with custom cert
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "secure")
	}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       srv.URL,
		VerifySsl: false,
		Regex:     "secure",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_HeadMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "HEAD",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_DeleteMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:            srv.URL,
		Method:         "DELETE",
		ExpectedStatus: 204,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestHTTPCheck_RegexOnEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// No body written
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: "something",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 (regex no match on empty body), got %d: %s", status, output)
	}
}

func TestHTTPCheck_MultipleRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		case "/c":
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, "final")
		}
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:             srv.URL + "/a",
		FollowRedirects: true,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 after multiple redirects, got %d: %s", status, output)
	}
}

func TestHTTPCheck_EmptyHeadersMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output, _ := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:     srv.URL,
		Headers: map[string]string{},
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 with empty headers, got %d: %s", status, output)
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// portFromListener extracts the port string from a net.Listener's address.
func portFromListener(ln net.Listener) string {
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// parsePort converts a port string to uint32 for use in proto configs.
func parsePort(s string) uint32 {
	var port uint32
	_, _ = fmt.Sscanf(s, "%d", &port)
	return port
}
