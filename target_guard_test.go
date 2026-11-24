// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/towerops-app/towerops-agent/pb"
)

func withDenyPrivateTargets(t *testing.T, deny bool) {
	t.Helper()
	orig := agentRuntimeSettings()
	next := orig
	next.DenyPrivateTargets = deny
	configureAgentRuntime(next)
	t.Cleanup(func() { configureAgentRuntime(orig) })
}

// Issue 5139: a cloud poller must refuse every dial to a non-routable
// address. Control sees the literal the socket connects to, so this matrix
// covers what no DNS stub could dodge.
func TestPrivateTargetControlClassifies(t *testing.T) {
	withDenyPrivateTargets(t, true)

	for _, tc := range []struct {
		name    string
		address string
		deny    bool
	}{
		{"loopback v4", "127.0.0.1:80", true},
		{"loopback range", "127.53.0.9:8080", true},
		{"loopback v6", "[::1]:443", true},
		{"rfc1918 10/8", "10.0.0.5:53", true},
		{"rfc1918 172.16/12", "172.16.0.1:22", true},
		{"rfc1918 192.168/16", "192.168.1.1:80", true},
		{"cgnat 100.64/10", "100.64.0.1:80", true},
		{"link-local metadata", "169.254.169.254:80", true},
		{"link-local v6", "[fe80::1]:80", true},
		{"ula", "[fd00::1]:80", true},
		{"unspecified", "0.0.0.0:80", true},
		{"multicast", "239.1.1.1:80", true},
		{"reserved 240/4", "255.255.255.255:80", true},
		{"this-network 0/8", "0.1.2.3:80", true},
		{"benchmark 198.18/15", "198.18.0.1:80", true},
		{"ipv4-mapped loopback", "[::ffff:127.0.0.1]:80", true},
		{"ipv4-mapped rfc1918", "[::ffff:10.0.0.5]:80", true},
		{"6to4 private", "[2002:a00:5::]:80", true},
		{"teredo private server", "[2001:0:a00:5:1:2:3:4]:80", true},
		{"teredo private client", "[2001:0:4136:e378:8000:63bf:f5ff:fffa]:80", true},
		{"public v4", "8.8.8.8:53", false},
		{"public v6", "[2606:4700:4700::1111]:443", false},
		{"rfc1918-adjacent but outside", "172.15.0.1:22", false},
		{"not a literal", "not-an-ip", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := privateTargetControl("tcp", tc.address, nil)
			if tc.deny && err == nil {
				t.Fatalf("%s was allowed", tc.address)
			}
			if !tc.deny && err != nil {
				t.Fatalf("%s refused: %v", tc.address, err)
			}
		})
	}
}

func TestPrivateTargetControlOffAllowsEverything(t *testing.T) {
	withDenyPrivateTargets(t, false)
	if err := privateTargetControl("tcp", "127.0.0.1:80", nil); err != nil {
		t.Fatalf("deny mode off must not refuse: %v", err)
	}
}

func TestCheckTransportDropsProxyInDenyMode(t *testing.T) {
	withDenyPrivateTargets(t, true)
	transport := newCheckHTTPTransport(false)
	if transport.Proxy != nil {
		t.Fatal("deny mode must validate the target, not a proxy address")
	}
	if transport.DialContext == nil {
		t.Fatal("guarded dialer missing")
	}
}

// The counting listener proves the refusal happens before any bytes reach
// the target: a check against its own port never produces an accept.
func acceptCounter(t *testing.T) (*net.TCPAddr, *int32, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var count int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count++
			_ = conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr), &count, func() { _ = ln.Close(); <-done }
}

// Issue 5139: with deny mode on, every check dial path refuses a private
// target and returns the same message the server's cloud executor uses.
func TestDenyPrivateTargetsRefusesChecks(t *testing.T) {
	withDenyPrivateTargets(t, true)
	ctx := context.Background()

	var httpHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpHits++
	}))
	defer srv.Close()

	assertRefused := func(t *testing.T, status uint32, output string) {
		t.Helper()
		if status != checkCritical {
			t.Fatalf("status = %d, want CRITICAL", status)
		}
		if output != errPrivateTarget.Error() {
			t.Fatalf("output = %q, want %q", output, errPrivateTarget.Error())
		}
	}

	t.Run("http loopback literal", func(t *testing.T) {
		status, output := executeHTTPCheck(ctx, &pb.HttpCheckConfig{Url: srv.URL}, 5000)
		assertRefused(t, status, output)
		if httpHits != 0 {
			t.Fatalf("target received %d requests", httpHits)
		}
	})

	t.Run("http ipv6 loopback", func(t *testing.T) {
		status, output := executeHTTPCheck(ctx, &pb.HttpCheckConfig{Url: "http://[::1]:9/"}, 5000)
		assertRefused(t, status, output)
	})

	t.Run("http link-local metadata", func(t *testing.T) {
		status, output := executeHTTPCheck(ctx,
			&pb.HttpCheckConfig{Url: "http://169.254.169.254/latest/meta-data/"}, 5000)
		assertRefused(t, status, output)
	})

	t.Run("http hostname resolving to loopback", func(t *testing.T) {
		// "localhost" resolves through the system resolver; the refusal on
		// the resolved literal is the same code a private DNS answer hits.
		port := srv.Listener.Addr().(*net.TCPAddr).Port
		status, output := executeHTTPCheck(ctx, &pb.HttpCheckConfig{
			Url: "http://localhost:" + strconv.Itoa(port) + "/",
		}, 5000)
		assertRefused(t, status, output)
	})

	addr, accepted, stop := acceptCounter(t)
	t.Cleanup(stop)
	port := uint32(addr.Port)

	t.Run("tcp loopback", func(t *testing.T) {
		status, output := executeTCPCheck(ctx, &pb.TcpCheckConfig{Host: "127.0.0.1", Port: port}, 5000)
		assertRefused(t, status, output)
	})

	t.Run("ssl loopback", func(t *testing.T) {
		status, output := executeSSLCheck(ctx, &pb.SslCheckConfig{Host: "127.0.0.1", Port: port}, 5000)
		assertRefused(t, status, output)
	})

	t.Run("dns private resolver", func(t *testing.T) {
		status, output := executeDNSCheck(ctx, &pb.DnsCheckConfig{
			Hostname: "example.com", Server: "127.0.0.1",
		}, 5000)
		assertRefused(t, status, output)
	})

	if *accepted != 0 {
		t.Fatalf("refused checks still reached the listener: %d accepts", *accepted)
	}
}

// With deny mode off nothing changes: the loopback listener answers as
// before. This is the on-prem agent default.
func TestDenyPrivateTargetsOffKeepsLoopbackReachable(t *testing.T) {
	withDenyPrivateTargets(t, false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	status, output := executeHTTPCheck(context.Background(), &pb.HttpCheckConfig{Url: srv.URL}, 5000)
	if status != checkOK {
		t.Fatalf("status = %d, output = %q; loopback must stay reachable without the flag", status, output)
	}
}
