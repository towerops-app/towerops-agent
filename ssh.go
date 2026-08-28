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
var sshDial = func(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, channels, requests), nil
}
var doPing = pingDevice

// executeMikrotikBackup connects via SSH and runs /export compact.
func executeMikrotikBackup(ip string, port uint16, username, password string) (string, error) {
	return executeMikrotikBackupContext(context.Background(), ip, port, username, password)
}

func executeMikrotikBackupContext(ctx context.Context, ip string, port uint16, username, password string) (string, error) {
	// SECURITY: TOFU (Trust-On-First-Use) host key verification.
	// On first connection the key is stored; subsequent connections reject mismatches.
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: sshHostKeyCallback(),
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	conn, err := sshDial(ctx, "tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	session, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput("/export compact")
	if err != nil {
		if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
			return "", fmt.Errorf("ssh command: %w: %s", err, trimmed)
		}
		return "", fmt.Errorf("ssh command: %w", err)
	}

	return string(output), nil
}

// executePingJob pings a device and sends a monitoring check result.
func executePingJob(ctx context.Context, job *pb.AgentJob, resultCh chan<- *pb.MonitoringCheck) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing device info for ping", "job_id", job.JobId)
		sendResult(ctx, resultCh, &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: time.Now().Unix(),
		}, job.JobId)
		return
	}

	timestamp := time.Now().Unix()
	responseTime, err := doPing(ctx, dev.Ip, 5000)

	if err != nil {
		slog.Warn("device down", "device", job.DeviceId, "error", err)
		sendResult(ctx, resultCh, &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: timestamp,
		}, job.JobId)
		return
	}

	slog.Debug("device up", "device", job.DeviceId, "response_time_ms", responseTime)
	sendResult(ctx, resultCh, &pb.MonitoringCheck{
		DeviceId:       job.DeviceId,
		Status:         "success",
		ResponseTimeMs: responseTime,
		Timestamp:      timestamp,
	}, job.JobId)
}
