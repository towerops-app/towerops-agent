// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

var sshBackup = executeMikrotikBackupContext
var sshBackupTimeout = 60 * time.Second

// sshBackupMaxOutputBytes bounds the /export output a legacy SSH backup will
// hold in memory. It is a var so tests can shrink it like sshBackupTimeout.
var sshBackupMaxOutputBytes uint64 = defaultMaxConfigBytes
var sshDial = func(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	clientConn, channels, requests, err := ssh.NewClientConn(conn, addr, config)
	stopCancel()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, channels, requests), nil
}
var doPing = pingDevice

// sshResolve resolves a dial target to the canonical remote address form —
// the same remote.String() the TOFU callback pins host keys under. It is a
// var so tests can fake DNS.
var sshResolve = func(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	// Unmap folds an IPv4-mapped IPv6 literal to plain IPv4, the form the
	// handshake's remote address reports. A lookup cannot come back empty
	// with a nil error: the resolver reports zero answers as errNoSuchHost.
	return net.JoinHostPort(addrs[0].Unmap().String(), port), nil
}

// sshClientAlive reports whether the connection still answers a keepalive
// request. RouterOS 6 closes the exec channel without an exit status while
// the transport stays usable; a device that dropped mid-export closes the
// whole connection and the request fails. That is what separates a
// RouterOS-style close that may succeed from a lost-connection close whose
// partial output must not be stored as a good backup.
func sshClientAlive(c *ssh.Client) bool {
	_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
	return err == nil
}

// redactBackupDetail mirrors configBackupError: scrub the credentials the
// legacy SSH backup carries, then shorten device output to one 300-byte
// line before it can reach an error field.
func redactBackupDetail(detail, password string) string {
	return firstLine(redactConfigSecrets(detail, &pb.ConfigBackupJob{Password: password}), maxConfigBackupDetailLen)
}

// executeMikrotikBackupContext connects via SSH and bounds the complete export,
// including the handshake and command, so a stalled device cannot pin a worker.
func executeMikrotikBackupContext(ctx context.Context, ip string, port uint16, username, password string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sshBackupTimeout)
	defer cancel()

	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	// Resolve before the pin lookup: the TOFU store keys entries by the
	// resolved remote.String() the handshake callback reports, so a
	// hostname or non-canonical IPv6 dev.Ip would never find its pin under
	// the raw dial string. Dialing the resolved literal keeps the dialed
	// address identical to the resolved one even when DNS round-robins.
	resolved, err := sshResolve(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", addr, err)
	}

	// SECURITY: TOFU (Trust-On-First-Use) host key verification.
	// On first connection the key is stored; subsequent connections reject
	// mismatches. When a key is already pinned, HostKeyAlgorithms is
	// restricted to its type so an x/crypto preference change cannot make a
	// dual-key device present a different key and trip a false MITM error.
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: sshHostKeyCallback(),
	}

	legacySSHAlgorithms(config)

	if alg := getHostKeyStore().pinnedKeyAlgorithm("ssh:" + resolved); alg != "" {
		config.HostKeyAlgorithms = hostKeyAlgorithmsFor(alg)
	}

	conn, err := sshDial(ctx, "tcp", resolved, config)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	session, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// stdout and stderr are buffered separately and capped so a broken or
	// hostile device cannot grow the heap until the job deadline; crossing
	// the stdout cap closes the channel to abort the stream.
	outBuf := boundedBuffer{
		limit:      sshBackupMaxOutputBytes,
		onOverflow: func() { _ = session.Close() },
	}
	errBuf := boundedBuffer{limit: configBackupStderrCap}
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	err = session.Run("/export compact")
	// RouterOS 6 closes the exec channel without an exit-status, which
	// surfaces as *ssh.ExitMissingError with the output still delivered.
	// Tolerate it only while the connection still answers a keepalive: a
	// device that dropped mid-export closes the transport, which produces
	// the same error and must stay an error.
	var exitMissing *ssh.ExitMissingError
	if errors.As(err, &exitMissing) && sshClientAlive(conn) {
		err = nil
	}
	output := append(outBuf.Bytes(), errBuf.Bytes()...)
	if outBuf.overflow {
		return "", fmt.Errorf("ssh command: %w", errConfigBackupTooLarge)
	}
	if err != nil {
		if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
			return "", fmt.Errorf("ssh command: %w: %s", err, redactBackupDetail(trimmed, password))
		}
		return "", fmt.Errorf("ssh command: %w", err)
	}

	if failure := routerOSCommandFailure(string(errBuf.Bytes())); failure != nil {
		return "", fmt.Errorf("ssh command: %s", redactBackupDetail(failure.detail, password))
	}
	exportOutput := string(outBuf.Bytes())
	if code := classifyExportOutput(exportOutput); code != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		return "", fmt.Errorf("ssh command: %s: %s", code, redactBackupDetail(strings.TrimSpace(exportOutput), password))
	}
	return exportOutput, nil
}

// legacySSHAlgorithms widens the client config with the legacy algorithms
// old devices offer. It now serves every config backup vendor, not just
// RouterOS 6. Host keys and MACs stay unset — the defaults already include
// ssh-rsa, ssh-dss and hmac-sha1, and setting HostKeyAlgorithms explicitly
// would reorder x/crypto's preference list, which could make a multi-key
// device present a different key than the fingerprint a PROBE already
// recorded.
//
// KEX order matters: the defaults come first, then the insecure algorithms
// only old devices offer (group1-sha1, gex-sha1), then the rest of the
// supported set (dh16-sha512, gex-sha256) last. SSH picks the first
// client-listed algorithm the server accepts, and a RouterOS 6 with
// strong-crypto=no answers group exchange with a 1024-bit prime that
// x/crypto rejects — the GEX forms must sit behind every fixed group the
// device might offer.
func legacySSHAlgorithms(c *ssh.ClientConfig) {
	var defaults ssh.Config
	defaults.SetDefaults()
	supported, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	c.KeyExchanges = mergeAlgorithms(defaults.KeyExchanges, insecure.KeyExchanges, supported.KeyExchanges)
	c.Ciphers = mergeAlgorithms(defaults.Ciphers, insecure.Ciphers)
}

// mergeAlgorithms concatenates algorithm lists in order, dropping repeats.
func mergeAlgorithms(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, algo := range list {
			if !seen[algo] {
				seen[algo] = true
				out = append(out, algo)
			}
		}
	}
	return out
}

// hostKeyAlgorithmsFor maps a pinned key type to the signature algorithms
// that verify it. key.Type() reports an RSA key as "ssh-rsa", which is also
// the SHA-1 signature algorithm; offering only that fails negotiation with
// devices that disable SHA-1 (strong-crypto RouterOS, OpenSSH 8.8+), so RSA
// keys and certificates offer the SHA-2 variants first.
func hostKeyAlgorithmsFor(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01}
	}
	return []string{keyType}
}

const defaultPingTimeoutMs = 5000

// pingProbeCount is how many echo requests one ping job sends. One probe
// cannot express loss at all (it is either 0 or 100, and the status field
// already says which), so the job sends three and reports the share that
// got no reply on monitoring_check's packet_loss_percent. Three is the
// smallest count that distinguishes "dropping some packets" from
// "answering" and "dead" without tripling the job's wall time.
const pingProbeCount = 3

// executePingJob pings a device and sends a monitoring check result.
func executePingJob(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing device info for ping", "job_id", job.JobId)
		result := &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: time.Now().Unix(),
		}
		slog.Info("ping job complete", "device", job.DeviceId, "status", result.Status)
		sendResult(ctx, out, "monitoring_check", result, job.JobId)
		return
	}

	timestamp := time.Now().Unix()
	timeoutMs := int(job.PingTimeoutMs)
	if timeoutMs <= 0 {
		timeoutMs = defaultPingTimeoutMs
	}
	// The job's timeout budgets the whole round; each probe gets a share so
	// three timeouts still end inside the deadline the scheduler planned.
	probeTimeoutMs := timeoutMs / pingProbeCount
	if probeTimeoutMs <= 0 {
		probeTimeoutMs = 1
	}

	var firstRTT float64
	replies := 0
	var lastErr error
	for range pingProbeCount {
		rtt, err := doPing(ctx, dev.Ip, probeTimeoutMs)
		if err != nil {
			lastErr = err
			continue
		}
		if replies == 0 {
			firstRTT = rtt
		}
		replies++
	}
	lossPercent := float64(pingProbeCount-replies) * 100.0 / float64(pingProbeCount)

	if replies == 0 {
		slog.Warn("device down", "device", job.DeviceId, "error", lastErr)
		result := &pb.MonitoringCheck{
			DeviceId:          job.DeviceId,
			Status:            "failure",
			Timestamp:         timestamp,
			PacketLossPercent: lossPercent,
		}
		slog.Info("ping job complete", "device", job.DeviceId, "status", result.Status)
		sendResult(ctx, out, "monitoring_check", result, job.JobId)
		return
	}

	slog.Debug("device up", "device", job.DeviceId, "response_time_ms", firstRTT,
		"replies", replies, "probes", pingProbeCount)
	result := &pb.MonitoringCheck{
		DeviceId:          job.DeviceId,
		Status:            "success",
		ResponseTimeMs:    firstRTT,
		Timestamp:         timestamp,
		PacketLossPercent: lossPercent,
	}
	slog.Info("ping job complete", "device", job.DeviceId, "status", result.Status)
	sendResult(ctx, out, "monitoring_check", result, job.JobId)
}
