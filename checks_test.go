// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"pgregory.net/rapid"
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, "HTTP 200 OK") {
		t.Fatalf("expected HTTP 200 OK in output, got %s", output)
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

func TestHTTPCheck_TransportsPreserveProxySupport(t *testing.T) {
	for name, transport := range map[string]*http.Transport{
		"default":  defaultHTTPTransport,
		"insecure": insecureHTTPTransport,
	} {
		t.Run(name, func(t *testing.T) {
			if transport.Proxy == nil {
				t.Fatal("expected proxy lookup inherited from http.DefaultTransport")
			}
			if transport.MaxIdleConns != 100 || transport.MaxIdleConnsPerHost != 10 {
				t.Fatalf("unexpected idle connection limits: %d/%d",
					transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
			}
			if transport.IdleConnTimeout != 90*time.Second {
				t.Fatalf("unexpected idle connection timeout: %v", transport.IdleConnTimeout)
			}
		})
	}

	if insecureHTTPTransport.TLSClientConfig == nil ||
		!insecureHTTPTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected insecure transport to skip TLS verification")
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `[invalid`,
	}, 5000)

	if status != 3 {
		t.Fatalf("expected status 3 for invalid regex, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Invalid regex") {
		t.Fatalf("expected 'Invalid regex' in output, got %s", output)
	}

	httpRegexCacheMu.Lock()
	_, cached := httpRegexCache[`[invalid`]
	httpRegexCacheMu.Unlock()
	if cached {
		t.Fatal("expected invalid regex not to be cached")
	}
}

func TestHTTPRegexCache_ReusesCompiledPattern(t *testing.T) {
	httpRegexCacheMu.Lock()
	originalCache := httpRegexCache
	originalOrder := httpRegexCacheOrder
	httpRegexCache = make(map[string]*regexp.Regexp)
	httpRegexCacheOrder = nil
	httpRegexCacheMu.Unlock()
	t.Cleanup(func() {
		httpRegexCacheMu.Lock()
		httpRegexCache = originalCache
		httpRegexCacheOrder = originalOrder
		httpRegexCacheMu.Unlock()
	})

	first, err := cachedHTTPRegex(`Version \d+`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cachedHTTPRegex(`Version \d+`)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected the compiled regex instance to be reused")
	}

	httpRegexCacheMu.Lock()
	cacheSize := len(httpRegexCache)
	httpRegexCacheMu.Unlock()
	if cacheSize != 1 {
		t.Fatalf("expected one cached regex, got %d", cacheSize)
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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
	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(ctx, &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:   srv.URL,
		Regex: `MARKER_FOUND_HERE`,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 for regex match in large body, got %d: %s", status, output)
	}
}

func TestHTTPCheck_RegexBodyOverLimitIsExplicit(t *testing.T) {
	bigBody := strings.Repeat("a", maxHTTPRegexBody) + "MARKER_BEYOND_LIMIT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, bigBody)
	}))
	defer srv.Close()

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url: srv.URL, Regex: `MARKER_BEYOND_LIMIT`,
	}, 5000)
	if status != 3 || !strings.Contains(output, "exceeds regex limit") {
		t.Fatalf("status/output = %d/%q, want explicit size-limit result", status, output)
	}
}

func TestHTTPCheck_SlowServerTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, fmt.Sprintf("TCP port %d open", port)) {
		t.Fatalf("expected port open message, got %s", output)
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   port,
		Send:   "hello\n",
		Expect: "ECHO:hello",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
}

func TestTCPCheck_ExpectBannerWithoutSend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 smtp.example ready\r\n"))
	}()

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1", Port: parsePort(portFromListener(ln)), Expect: "ready",
	}, 1000)
	if status != 0 {
		t.Fatalf("status = %d, want 0: %s", status, output)
	}
}

func TestTCPCheck_ExpectMaySpanReads(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buffer := make([]byte, 16)
		_, _ = conn.Read(buffer)
		_, _ = conn.Write([]byte("EXPEC"))
		time.Sleep(10 * time.Millisecond)
		_, _ = conn.Write([]byte("TED"))
	}()

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1", Port: parsePort(portFromListener(ln)), Send: "hello", Expect: "EXPECTED",
	}, 1000)
	if status != 0 {
		t.Fatalf("status = %d, want 0: %s", status, output)
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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
	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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
	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
}

func TestDNSCheck_AAAARecord(t *testing.T) {
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "this-domain-does-not-exist-towerops-test.invalid",
		RecordType: "A",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for NXDOMAIN, got %d: %s", status, output)
	}
}

func TestDNSCheck_DefaultRecordTypeIsA(t *testing.T) {
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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

	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "example.com",
		RecordType: "A",
		Server:     "8.8.8.8",
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 with custom DNS server, got %d: %s", status, output)
	}
}

func TestResolverForServerUsesRequestedNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	resolver := resolverForServer(ln.Addr().String(), time.Second)
	conn, err := resolver.Dial(context.Background(), "tcp", "unused")
	if err != nil {
		t.Fatalf("dial requested TCP network: %v", err)
	}
	_ = conn.Close()
}

func TestDNSCheck_RecordTypeCaseInsensitive(t *testing.T) {
	// The code does strings.ToUpper, so lowercase should work
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "this-domain-does-not-exist-towerops-test.invalid",
		RecordType: "AAAA",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2, got %d: %s", status, output)
	}
}

func TestDNSCheck_VeryShortTimeout(t *testing.T) {
	// Use a custom DNS server with 1ms timeout - should timeout
	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
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

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:    srv.URL,
		Method: "put", // lowercase
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
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

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:     srv.URL,
		Headers: map[string]string{},
	}, 5000)

	if status != 0 {
		t.Fatalf("expected status 0 with empty headers, got %d: %s", status, output)
	}
}

// ---------------------------------------------------------------------------
// SSL check tests
// ---------------------------------------------------------------------------

func TestCertificateDaysRemainingRecentlyExpired(t *testing.T) {
	now := time.Now()
	days, expired := certificateDaysRemaining(now, now.Add(-time.Hour))
	if !expired {
		t.Fatal("certificate expired one hour ago was not classified as expired")
	}
	if days != 0 {
		t.Fatalf("days = %d, want 0 for a certificate expired less than one day", days)
	}
}

func TestExecuteCheck_MissingSSLConfig(t *testing.T) {
	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-ssl-missing",
		CheckType: "ssl",
		TimeoutMs: 5000,
	})
	if result.Status != 3 {
		t.Fatalf("expected status 3, got %d", result.Status)
	}
	if !strings.Contains(result.Output, "Missing SSL config") {
		t.Fatalf("expected missing SSL config message, got %s", result.Output)
	}
}

func TestExecuteCheck_SSLRouting(t *testing.T) {
	// Start a local TLS server with a self-signed cert
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTestSSLRootCA(t, srv.Certificate())

	// Parse the port from the test server URL
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))

	result := ExecuteCheck(context.Background(), &pb.Check{
		Id:        "chk-route-ssl",
		CheckType: "ssl",
		TimeoutMs: 5000,
		Config: &pb.Check_Ssl{
			Ssl: &pb.SslCheckConfig{
				Host:        "127.0.0.1",
				Port:        parsePort(portStr),
				WarningDays: 7,
			},
		},
	})
	// The test server has a valid cert, so should be OK
	if result.Status == 3 {
		t.Fatalf("expected routing to SSL handler, got status 3 (UNKNOWN): %s", result.Output)
	}
}

func TestSSLCheck_ValidCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTestSSLRootCA(t, srv.Certificate())

	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 1,
	}, 5000)

	// httptest TLS cert is valid, should be OK with warning_days=1
	if status != 0 {
		t.Fatalf("expected status 0, got %d: %s", status, output)
	}
	if !strings.Contains(output, "OK: Certificate") {
		t.Fatalf("expected OK message, got %s", output)
	}
}

func TestSSLCheck_WarningThreshold(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTestSSLRootCA(t, srv.Certificate())

	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	// httptest certs typically expire within a few years.
	// Set warning_days very high to trigger WARNING.
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 999999,
	}, 5000)

	if status != 1 {
		t.Fatalf("expected status 1 (WARNING), got %d: %s", status, output)
	}
	if !strings.Contains(output, "WARNING: Certificate") {
		t.Fatalf("expected WARNING message, got %s", output)
	}
}

func TestSSLCheck_ConnectionFailure(t *testing.T) {
	// Use non-routable address
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "192.0.2.1",
		Port: 443,
	}, 1000)

	if status != 3 {
		t.Fatalf("expected status 3 (UNKNOWN), got %d: %s", status, output)
	}
	if !strings.Contains(output, "Connection failed") {
		t.Fatalf("expected connection failed message, got %s", output)
	}
}

func TestSSLCheck_HonorsCancelledContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	status, _ := executeSSLCheck(ctx, &pb.SslCheckConfig{
		Host: "127.0.0.1",
		Port: parsePort(portFromListener(ln)),
	}, 5000)
	if status != 3 {
		t.Fatalf("expected status 3, got %d", status)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled check took %v", elapsed)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
	}
}

func TestSSLCheck_ClosedPort(t *testing.T) {
	// Bind and immediately close to get a port that refuses connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := parsePort(portFromListener(ln))
	_ = ln.Close()

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 2000)

	if status != 3 {
		t.Fatalf("expected status 3, got %d: %s", status, output)
	}
}

func TestSSLCheck_DefaultPort443(t *testing.T) {
	// When port is 0 (unset), should default to 443.
	// We just verify it doesn't crash.
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "192.0.2.1",
		Port: 0,
	}, 500)

	// Should fail to connect (non-routable), but shouldn't crash
	if status != 3 {
		t.Logf("SSL check with default port returned status %d: %s", status, output)
	}
}

func TestSSLCheck_DefaultWarningDays30(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTestSSLRootCA(t, srv.Certificate())

	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	// warning_days=0 should default to 30
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 0,
	}, 5000)

	// httptest certs are valid for ~1 year, with default 30 days warning should be OK
	if status != 0 {
		t.Fatalf("expected status 0 with default warning_days, got %d: %s", status, output)
	}
}

func TestSSLCheck_SelfSignedCertificateIsCritical(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 7,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for untrusted certificate, got %d: %s", status, output)
	}
	if !strings.Contains(output, "CRITICAL: Certificate for") ||
		!strings.Contains(output, "is not trusted:") {
		t.Fatalf("expected certificate trust failure output, got %s", output)
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

func withTestSSLRootCA(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	orig := sslRootCAs
	sslRootCAs = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return pool, nil
	}
	t.Cleanup(func() { sslRootCAs = orig })
}

// ---------------------------------------------------------------------------
// chkT: branch coverage for checks.go error paths
// ---------------------------------------------------------------------------

// chkTOrigSslRootCAs captures the production sslRootCAs implementation before
// any test can replace it.
var chkTOrigSslRootCAs = sslRootCAs

// chkTRawHTTPServer serves a hand-written HTTP response and then closes the
// connection, which lets tests force response-body read failures.
func chkTRawHTTPServer(t *testing.T, header string, body []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				if _, err := conn.Write([]byte(header)); err != nil {
					return
				}
				_, _ = conn.Write(body)
			}()
		}
	}()

	return "http://" + ln.Addr().String()
}

func TestChkTHTTPCheckBodyReadErrorWithRegex(t *testing.T) {
	url := chkTRawHTTPServer(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n",
		[]byte("truncated"))

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       url,
		Regex:     "truncated",
		VerifySsl: true,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for truncated body, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Failed to read body") {
		t.Fatalf("expected read-body failure, got %s", output)
	}
}

func TestChkTHTTPCheckDrainErrorAfterRegexLimit(t *testing.T) {
	// io.ReadAll fills the regex limit without error, then the drain io.Copy
	// hits the truncated body.
	body := bytes.Repeat([]byte("a"), maxHTTPRegexBody+4096)
	url := chkTRawHTTPServer(t,
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", maxHTTPRegexBody*4),
		body)

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       url,
		Regex:     "aaa",
		VerifySsl: true,
	}, 10000)

	if status != 2 {
		t.Fatalf("expected status 2 for drain failure, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Failed to read body") {
		t.Fatalf("expected read-body failure, got %s", output)
	}
}

func TestChkTHTTPCheckDrainErrorWithoutRegex(t *testing.T) {
	url := chkTRawHTTPServer(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n",
		[]byte("truncated"))

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{
		Url:       url,
		VerifySsl: true,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for truncated body, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Failed to read body") {
		t.Fatalf("expected read-body failure, got %s", output)
	}
}

// chkTDeadlineErrConn is a net.Conn whose SetDeadline always fails.
type chkTDeadlineErrConn struct {
	net.Conn
}

func (c *chkTDeadlineErrConn) SetDeadline(time.Time) error {
	return errors.New("chkT deadline unsupported")
}

func TestChkTTCPCheckSetDeadlineFailure(t *testing.T) {
	orig := tcpDialContext
	defer func() { tcpDialContext = orig }()

	tcpDialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return &chkTDeadlineErrConn{Conn: client}, nil
	}

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host: "127.0.0.1",
		Port: 1234,
		Send: "PING\r\n",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 when SetDeadline fails, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Set deadline failed") {
		t.Fatalf("expected set-deadline failure, got %s", output)
	}
	if !strings.Contains(output, "chkT deadline unsupported") {
		t.Fatalf("expected wrapped conn error, got %s", output)
	}
}

func TestTCPCheck_LongBinaryMismatchOutputIsBoundedAndPrintable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// 80 KiB of binary filler pushes the read loop past its 64 KiB budget
	// without ever containing the expected banner.
	filler := bytes.Repeat([]byte{0x00, 0x01, 0x02, 'x', 0xff}, 16<<10)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = conn.Write(filler)
			}()
		}
	}()

	status, output := executeTCPCheck(context.Background(), &pb.TcpCheckConfig{
		Host:   "127.0.0.1",
		Port:   parsePort(portFromListener(ln)),
		Expect: "chkT-never-sent",
	}, 10000)

	if status != 2 {
		t.Fatalf("expected status 2 when expect never matches, got %d", status)
	}
	if !strings.HasPrefix(output, "Unexpected response: ") {
		t.Fatalf("expected unexpected-response output, got %.60s", output)
	}
	if len(output) > len("Unexpected response: ")+maxTCPOutputBytes+64 {
		t.Fatalf("expected bounded output, got %d bytes", len(output))
	}
	if !strings.Contains(output, "bytes received") {
		t.Fatalf("expected true response size note, got %q", output)
	}
	for _, b := range []byte(output) {
		if b < 0x20 || b > 0x7e {
			t.Fatalf("expected printable ASCII output, found byte 0x%02x", b)
		}
	}
}

func TestTCPResponseForOutput_TruncatesSanitizesAndReportsByteCount(t *testing.T) {
	response := bytes.Repeat([]byte{0x00, 'A', 0xff}, maxTCPOutputBytes)
	output := tcpResponseForOutput(response)

	if len(output) > maxTCPOutputBytes+64 {
		t.Fatalf("expected bounded output, got %d bytes", len(output))
	}
	if !strings.Contains(output, fmt.Sprintf("%d bytes received", len(response))) {
		t.Fatalf("expected true response size in %q", output)
	}
	for _, b := range []byte(output) {
		if b < 0x20 || b > 0x7e {
			t.Fatalf("expected printable ASCII output, found byte 0x%02x", b)
		}
	}
}

// chkTZeroWriter accepts nothing while reporting success, which is the
// io.ErrShortWrite condition writeAll guards against.
type chkTZeroWriter struct {
	calls int
}

func (w *chkTZeroWriter) Write(p []byte) (int, error) {
	w.calls++
	return 0, nil
}

func TestChkTWriteAllShortWrite(t *testing.T) {
	w := &chkTZeroWriter{}
	err := writeAll(w, []byte("payload"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v", err)
	}
	if w.calls != 1 {
		t.Fatalf("expected writeAll to bail out after one write, got %d", w.calls)
	}
}

// Go's stub resolver reports "no such host" for an empty answer section, so a
// record-less success can only be produced through the lookup seam.
func TestChkTDNSCheckNoRecordsFound(t *testing.T) {
	orig := dnsLookupTXT
	defer func() { dnsLookupTXT = orig }()

	var gotHost string
	dnsLookupTXT = func(_ *net.Resolver, _ context.Context, host string) ([]string, error) {
		gotHost = host
		return nil, nil
	}

	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "chkt-empty.example",
		RecordType: "txt",
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for an empty record set, got %d: %s", status, output)
	}
	if output != "No TXT records found" {
		t.Fatalf("expected no-records output, got %s", output)
	}
	if gotHost != "chkt-empty.example" {
		t.Fatalf("expected the configured hostname to be looked up, got %q", gotHost)
	}
}

// Go returns CNAME and MX names as FQDNs with a trailing dot, so an operator
// who enters "example.com" used to get a permanent CRITICAL.
func TestChkTDNSAnswerMatches(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		results    []string
		expected   string
		want       bool
	}{
		{"cname answer keeps its trailing dot", "CNAME", []string{"example.com."}, "example.com", true},
		{"expected carries the trailing dot", "CNAME", []string{"example.com"}, "example.com.", true},
		{"cname mismatch", "CNAME", []string{"other.example.com."}, "example.com", false},
		{"mx preference and host", "MX", []string{"10 mx.example.com."}, "10 mx.example.com", true},
		{"mx host alone", "MX", []string{"10 mx.example.com."}, "mx.example.com", true},
		{"mx wrong preference", "MX", []string{"10 mx.example.com."}, "20 mx.example.com", false},
		{"mx picks the matching record", "MX", []string{"10 a.example.com.", "20 b.example.com."}, "b.example.com", true},
		{"txt is never split on spaces", "TXT", []string{"hello v=spf1"}, "v=spf1", false},
		{"address record", "A", []string{"10.0.0.2", "10.0.0.1"}, "10.0.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dnsAnswerMatches(tt.recordType, tt.results, tt.expected); got != tt.want {
				t.Fatalf("dnsAnswerMatches(%q, %v, %q) = %v, want %v",
					tt.recordType, tt.results, tt.expected, got, tt.want)
			}
		})
	}
}

// The lookup seam is the only way to feed executeDNSCheck a fixed answer, and
// it proves the trailing-dot handling is wired into the check itself.
func TestChkTDNSCheckExpectedIgnoresTrailingDot(t *testing.T) {
	orig := dnsLookupTXT
	defer func() { dnsLookupTXT = orig }()
	dnsLookupTXT = func(_ *net.Resolver, _ context.Context, _ string) ([]string, error) {
		return []string{"mail.example.com."}, nil
	}

	status, output := executeDNSCheck(context.Background(), &pb.DnsCheckConfig{
		Hostname:   "chkt-dot.example",
		RecordType: "TXT",
		Expected:   "mail.example.com",
	}, 5000)

	if status != checkOK {
		t.Fatalf("status = %d (%s), want OK for an answer differing only by the trailing dot", status, output)
	}
}

func TestChkTSslRootCAsSystemPoolError(t *testing.T) {
	origPool := sslRootCAsPool
	origSystem := systemCertPool
	defer func() {
		sslRootCAsPool = origPool
		systemCertPool = origSystem
	}()

	sslRootCAsPool = nil
	wantErr := errors.New("chkT no system roots")
	systemCertPool = func() (*x509.CertPool, error) { return nil, wantErr }

	pool, err := chkTOrigSslRootCAs()
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the system pool error, got %v", err)
	}
	if pool != nil {
		t.Fatalf("expected a nil pool on failure, got %v", pool)
	}
	if sslRootCAsPool != nil {
		t.Fatal("expected failures not to populate the cache")
	}
}

func TestChkTSSLCheckRootCALoadFailure(t *testing.T) {
	orig := sslRootCAs
	defer func() { sslRootCAs = orig }()
	sslRootCAs = func() (*x509.CertPool, error) {
		return nil, errors.New("chkT root store unavailable")
	}

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "127.0.0.1",
		Port: 443,
	}, 5000)

	if status != 3 {
		t.Fatalf("expected status 3 when root CAs fail to load, got %d: %s", status, output)
	}
	if !strings.Contains(output, "Failed to load system root CAs") {
		t.Fatalf("expected root CA failure output, got %s", output)
	}
}

func TestChkTSSLCheckNonTLSConnection(t *testing.T) {
	orig := sslDialTLS
	defer func() { sslDialTLS = orig }()
	sslDialTLS = func(_ context.Context, _ *net.Dialer, _ *tls.Config, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "127.0.0.1",
		Port: 8443,
	}, 5000)

	if status != 3 {
		t.Fatalf("expected status 3 for a non-TLS conn, got %d: %s", status, output)
	}
	if output != "Connection did not negotiate TLS" {
		t.Fatalf("expected TLS negotiation output, got %s", output)
	}
}

func TestChkTSSLCheckNoPeerCertificates(t *testing.T) {
	orig := sslDialTLS
	defer func() { sslDialTLS = orig }()
	sslDialTLS = func(_ context.Context, _ *net.Dialer, _ *tls.Config, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		// Never handshaked, so the connection state carries no peer certs.
		return tls.Client(client, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}), nil
	}

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host: "certless.chkt.test",
		Port: 9443,
	}, 5000)

	if status != 3 {
		t.Fatalf("expected status 3 without peer certs, got %d: %s", status, output)
	}
	if output != "No certificate presented by certless.chkt.test:9443" {
		t.Fatalf("expected no-certificate output, got %s", output)
	}
}

// chkTSelfSignedCert builds a self-signed leaf valid over the given window.
func chkTSelfSignedCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20260828),
		Subject:               pkix.Name{CommonName: "expired.chkt.test"},
		DNSNames:              []string{"expired.chkt.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestChkTSSLCheckExpiredCertificate(t *testing.T) {
	cert := chkTSelfSignedCert(t, time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))

	orig := sslDialTLS
	defer func() { sslDialTLS = orig }()
	sslDialTLS = func(ctx context.Context, _ *net.Dialer, cfg *tls.Config, _, _ string) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		t.Cleanup(func() { _ = serverRaw.Close() })

		go func() {
			server := tls.Server(serverRaw, &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			})
			_ = server.HandshakeContext(ctx)
		}()

		// Verification is deliberately skipped: the point of the check is what
		// executeSSLCheck concludes about an expired certificate.
		client := tls.Client(clientRaw, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: true,
		})
		if err := client.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return client, nil
	}

	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "expired.chkt.test",
		Port:        443,
		WarningDays: 30,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for an expired certificate, got %d: %s", status, output)
	}
	want := fmt.Sprintf("CRITICAL: Certificate for expired.chkt.test:443 expired 2 days ago (%s)",
		cert.Leaf.NotAfter.Format("2006-01-02"))
	if output != want {
		t.Fatalf("expected %q, got %q", want, output)
	}
}

func TestSSLCheck_ExpiredCertificateHandshakeIsCritical(t *testing.T) {
	cert := chkTSelfSignedCert(t, time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	srv.StartTLS()
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 30,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 rather than a handshake failure, got %d: %s", status, output)
	}
	if !strings.Contains(output, "expired 2 days ago") {
		t.Fatalf("expected certificate expiry output, got %s", output)
	}
}

func TestSSLCheck_NotYetValidCertificateIsCritical(t *testing.T) {
	cert := chkTSelfSignedCert(t, time.Now().Add(48*time.Hour), time.Now().Add(96*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	srv.StartTLS()
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	status, output := executeSSLCheck(context.Background(), &pb.SslCheckConfig{
		Host:        "127.0.0.1",
		Port:        parsePort(portStr),
		WarningDays: 30,
	}, 5000)

	if status != 2 {
		t.Fatalf("expected status 2 for a not-yet-valid certificate, got %d: %s", status, output)
	}
	if !strings.Contains(output, "is not valid until") {
		t.Fatalf("expected not-yet-valid output, got %s", output)
	}
}

// ---------------------------------------------------------------------------
// chkT: property tests
// ---------------------------------------------------------------------------

// chkTChunkWriter accepts at most chunk bytes per Write and optionally fails
// once failAfter bytes have been accepted.
type chkTChunkWriter struct {
	buf       bytes.Buffer
	chunk     int
	failAfter int // negative disables failures
	err       error
}

func (w *chkTChunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > w.chunk {
		n = w.chunk
	}
	if w.failAfter >= 0 {
		remaining := w.failAfter - w.buf.Len()
		if n >= remaining {
			w.buf.Write(p[:remaining])
			return remaining, w.err
		}
	}
	w.buf.Write(p[:n])
	return n, nil
}

func TestPropChkWriteAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(t, "data")
		chunk := rapid.IntRange(1, 64).Draw(t, "chunk")

		w := &chkTChunkWriter{chunk: chunk, failAfter: -1}
		if err := writeAll(w, data); err != nil {
			t.Fatalf("writeAll returned %v for %d bytes", err, len(data))
		}
		if !bytes.Equal(w.buf.Bytes(), data) {
			t.Fatalf("writer received %d bytes, want %d identical bytes", w.buf.Len(), len(data))
		}

		if len(data) == 0 {
			return
		}

		prefix := rapid.IntRange(0, len(data)-1).Draw(t, "prefix")
		wantErr := errors.New("chkT write failure")
		fw := &chkTChunkWriter{chunk: chunk, failAfter: prefix, err: wantErr}
		if err := writeAll(fw, data); !errors.Is(err, wantErr) {
			t.Fatalf("expected the writer error after %d bytes, got %v", prefix, err)
		}
		if fw.buf.Len() != prefix {
			t.Fatalf("writer accepted %d bytes, want %d", fw.buf.Len(), prefix)
		}
		if !bytes.Equal(fw.buf.Bytes(), data[:prefix]) {
			t.Fatal("writer received bytes out of order")
		}
	})
}

func TestPropChkCheckTimeout(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ms := rapid.IntRange(1, 4_000_000).Draw(t, "timeoutMs")

		got := checkTimeout(uint32(ms))
		if want := time.Duration(ms) * time.Millisecond; got != want {
			t.Fatalf("checkTimeout(%d) = %v, want %v", ms, got, want)
		}
		if got <= 0 {
			t.Fatalf("checkTimeout(%d) = %v, want a positive duration", ms, got)
		}
	})

	if got := checkTimeout(0); got != 10*time.Second {
		t.Fatalf("checkTimeout(0) = %v, want 10s", got)
	}
}
