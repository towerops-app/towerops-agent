// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// errPrivateTarget refuses a dial toward a loopback, private, link-local,
// multicast or otherwise non-routable address. The message matches the
// server's cloud executor refusal verbatim so a denied check reads the same
// whichever side stopped it.
var errPrivateTarget = errors.New("Cannot access private/internal IP addresses") //nolint:staticcheck // check output must match the server refusal string verbatim

// privateTargetPrefixes mirrors @private_cidrs in the server's
// Towerops.Net.Cidr: the ranges an outbound connection must never reach when
// the agent runs as the shared multi-tenant cloud poller (issue 5139).
var privateTargetPrefixes = mustParsePrefixes([]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"192.0.0.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"0.0.0.0/8",
	"198.18.0.0/15",
	"fc00::/7",
	"fe80::/10",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"::/96",
	"::1/128",
	"ff00::/8",
	"100::/64",
})

func mustParsePrefixes(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
}

// privateTargetControl is a net.Dialer Control hook installed on every
// server-directed dial. Control runs after DNS resolution on the literal
// address the socket connects to, so one hook covers hostnames that resolve
// private, DNS answers that change between runs, and every HTTP redirect
// hop, with no per-executor logic. It is a no-op unless the poller opts in
// with --deny-private-targets (issue 5139).
func privateTargetControl(_, address string, _ syscall.RawConn) error {
	if !agentRuntimeSettings().DenyPrivateTargets {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if privateTargetIP(host) {
		return errPrivateTarget
	}
	return nil
}

// privateTargetDialer is the shared dialer for check transports: the same
// timeouts as http.DefaultTransport's dialer plus the private-target guard.
var privateTargetDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	Control:   privateTargetControl,
}

// privateTargetIP reports whether host is an IP literal inside a denied
// range, including an IPv4-mapped form and the IPv4 a 6to4 or Teredo address
// embeds. Non-literals answer false: what a name resolves to is settled by
// Control on the resolved address, not here.
func privateTargetIP(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if inPrivateTargetRanges(addr) {
		return true
	}
	return embeddedPrivateIPv4(addr)
}

func inPrivateTargetRanges(addr netip.Addr) bool {
	for _, prefix := range privateTargetPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// embeddedPrivateIPv4 unwraps the IPv4 an IPv6 transition address routes to:
// 6to4 (2002::/16) carries it in bits 16-48, Teredo (2001::/32) in the server
// field and XOR-obfuscated in the client field. Either being private makes
// the destination non-routable, matching the server's private_forms check.
func embeddedPrivateIPv4(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	b := addr.As16()
	switch {
	case b[0] == 0x20 && b[1] == 0x02:
		return inPrivateTargetRanges(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0:
		server := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
		client := netip.AddrFrom4([4]byte{b[12] ^ 0xFF, b[13] ^ 0xFF, b[14] ^ 0xFF, b[15] ^ 0xFF})
		return inPrivateTargetRanges(server) || inPrivateTargetRanges(client)
	}
	return false
}
