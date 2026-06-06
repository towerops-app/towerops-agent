package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"codeberg.org/towerops-agent/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

var sshBackup = executeMikrotikBackup
var sshDial = ssh.Dial
var doPing = pingDevice

// executeMikrotikBackup connects via SSH and runs /export compact.
func executeMikrotikBackup(ip string, port uint16, username, password string) (string, error) {
	// SECURITY: TOFU (Trust-On-First-Use) host key verification.
	// On first connection the key is stored; subsequent connections reject mismatches.
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: sshHostKeyCallback(),
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	conn, err := sshDial("tcp", addr, config)
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
		sendMonitoringCheckWithTimeout(ctx, resultCh, &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: time.Now().Unix(),
		}, job.JobId)
		return
	}

	timestamp := time.Now().Unix()
	responseTime, err := doPing(dev.Ip, 5000)

	if err != nil {
		slog.Warn("device down", "device", job.DeviceId, "error", err)
		sendMonitoringCheckWithTimeout(ctx, resultCh, &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: timestamp,
		}, job.JobId)
		return
	}

	slog.Debug("device up", "device", job.DeviceId, "response_time_ms", responseTime)
	sendMonitoringCheckWithTimeout(ctx, resultCh, &pb.MonitoringCheck{
		DeviceId:       job.DeviceId,
		Status:         "success",
		ResponseTimeMs: responseTime,
		Timestamp:      timestamp,
	}, job.JobId)
}

func sendMonitoringCheckWithTimeout(ctx context.Context, resultCh chan<- *pb.MonitoringCheck, result *pb.MonitoringCheck, jobID string) {
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case resultCh <- result:
	case <-sendCtx.Done():
		slog.Error("monitoring check result send timeout - agent overloaded", "job_id", jobID)
	}
}
