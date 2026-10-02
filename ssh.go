// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
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

// executeMikrotikBackupContext connects via SSH and bounds the complete export,
// including the handshake and command, so a stalled device cannot pin a worker.
func executeMikrotikBackupContext(ctx context.Context, ip string, port uint16, username, password string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sshBackupTimeout)
	defer cancel()

	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))

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
	if alg := getHostKeyStore().pinnedKeyAlgorithm("ssh:" + addr); alg != "" {
		config.HostKeyAlgorithms = hostKeyAlgorithmsFor(alg)
	}

	conn, err := sshDial(ctx, "tcp", addr, config)
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
	output := append(outBuf.Bytes(), errBuf.Bytes()...)
	if outBuf.overflow {
		return "", fmt.Errorf("ssh command: %w", errConfigBackupTooLarge)
	}
	if err != nil {
		if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
			return "", fmt.Errorf("ssh command: %w: %s", err, trimmed)
		}
		return "", fmt.Errorf("ssh command: %w", err)
	}

	return string(output), nil
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
	responseTime, err := doPing(ctx, dev.Ip, timeoutMs)

	if err != nil {
		slog.Warn("device down", "device", job.DeviceId, "error", err)
		result := &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: timestamp,
		}
		slog.Info("ping job complete", "device", job.DeviceId, "status", result.Status)
		sendResult(ctx, out, "monitoring_check", result, job.JobId)
		return
	}

	slog.Debug("device up", "device", job.DeviceId, "response_time_ms", responseTime)
	result := &pb.MonitoringCheck{
		DeviceId:       job.DeviceId,
		Status:         "success",
		ResponseTimeMs: responseTime,
		Timestamp:      timestamp,
	}
	slog.Info("ping job complete", "device", job.DeviceId, "status", result.Status)
	sendResult(ctx, out, "monitoring_check", result, job.JobId)
}
