package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

var sshBackup = executeMikrotikBackup
var doPing = pingDevice

// executeMikrotikBackup connects via SSH and runs /export compact.
func executeMikrotikBackup(ip string, port uint16, username, password string) (string, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := ssh.Dial("tcp", addr, config)
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
		// MikroTik SSH doesn't use exit codes the same way - check if we got output
		if len(output) > 0 {
			return string(output), nil
		}
		return "", fmt.Errorf("ssh command: %w", err)
	}

	return string(output), nil
}

// executePingJob pings a device and sends a monitoring check result.
func executePingJob(job *pb.AgentJob, resultCh chan<- *pb.MonitoringCheck) {
	dev := job.SnmpDevice
	if dev == nil {
		slog.Error("job missing device info for ping", "job_id", job.JobId)
		return
	}

	timestamp := time.Now().Unix()
	responseTime, err := doPing(dev.Ip, 5000)

	if err != nil {
		slog.Warn("device down", "device", job.DeviceId, "error", err)
		resultCh <- &pb.MonitoringCheck{
			DeviceId:  job.DeviceId,
			Status:    "failure",
			Timestamp: timestamp,
		}
		return
	}

	slog.Debug("device up", "device", job.DeviceId, "response_time_ms", responseTime)
	resultCh <- &pb.MonitoringCheck{
		DeviceId:       job.DeviceId,
		Status:         "success",
		ResponseTimeMs: responseTime,
		Timestamp:      timestamp,
	}
}
