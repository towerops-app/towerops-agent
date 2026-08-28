// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

const (
	mikrotikConnTimeout  = 30 * time.Second
	mikrotikReadTimeout  = 30 * time.Second
	maxMikrotikWordSize  = 10 << 20 // 10 MB
	maxMikrotikResponse  = 16 << 20 // 16 MB aggregate decoded response
	maxMikrotikWords     = 10000
	maxMikrotikSentences = 10000
)

var mikrotikDial = mikrotikConnect

// mikrotikClient is a RouterOS binary API client.
type mikrotikClient struct {
	conn io.ReadWriteCloser
}

type mikrotikSentence struct {
	attributes map[string]string
}

type mikrotikResponse struct {
	sentences []mikrotikSentence
	err       string
}

// mikrotikConnect connects and authenticates to a MikroTik device.
func mikrotikConnect(ctx context.Context, ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error

	if useSSL {
		// SECURITY: InsecureSkipVerify is used because MikroTik devices use
		// self-signed certificates. TOFU verification of the cert fingerprint
		// is performed after the handshake to detect MITM attacks.
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: mikrotikConnTimeout},
			Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}
		dialCtx, dialCancel := context.WithTimeout(ctx, mikrotikConnTimeout)
		defer dialCancel()
		conn, err = dialer.DialContext(dialCtx, "tcp", addr)
		if err == nil {
			// Verify TLS cert fingerprint via TOFU
			tlsConn, ok := conn.(*tls.Conn)
			if ok && len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				fp := tlsCertFingerprint(tlsConn.ConnectionState().PeerCertificates[0])
				if verifyErr := getHostKeyStore().verify("tls:"+addr, fp); verifyErr != nil {
					_ = conn.Close()
					return nil, fmt.Errorf("TLS TOFU verification failed for %s: %w", addr, verifyErr)
				}
			}
		}
	} else {
		dialer := net.Dialer{Timeout: mikrotikConnTimeout}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}

	c := &mikrotikClient{conn: conn}

	// Authenticate
	resp, err := c.execute("/login", map[string]string{"name": username, "password": password})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if resp.err != "" {
		_ = conn.Close()
		return nil, fmt.Errorf("auth failed: %s", resp.err)
	}

	return c, nil
}

// execute sends a command and reads the full response.
func (c *mikrotikClient) execute(command string, args map[string]string) (*mikrotikResponse, error) {
	words := []string{command}
	for k, v := range args {
		if strings.HasPrefix(k, "?") || strings.HasPrefix(k, ".") {
			words = append(words, k+"="+v)
		} else {
			words = append(words, "="+k+"="+v)
		}
	}

	if err := c.writeSentence(words); err != nil {
		return nil, err
	}

	return c.readResponse()
}

func (c *mikrotikClient) close() error {
	_, _ = c.execute("/quit", nil) // best-effort
	return c.conn.Close()
}

func (c *mikrotikClient) writeSentence(words []string) error {
	var buf []byte
	for _, w := range words {
		buf = append(buf, encodeLength(len(w))...)
		buf = append(buf, w...)
	}
	buf = append(buf, 0) // empty word terminates sentence

	return writeAll(c.conn, buf)
}

func (c *mikrotikClient) readResponse() (*mikrotikResponse, error) {
	resp := &mikrotikResponse{}
	totalBytes := 0

	for sentenceCount := 0; sentenceCount < maxMikrotikSentences; sentenceCount++ {
		words, err := c.readSentence()
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		for _, word := range words {
			totalBytes += len(word)
			if totalBytes > maxMikrotikResponse {
				return nil, fmt.Errorf("response exceeds %d bytes", maxMikrotikResponse)
			}
		}

		switch words[0] {
		case "!done":
			attrs := parseMikrotikAttrs(words[1:])
			if len(attrs) > 0 {
				resp.sentences = append(resp.sentences, mikrotikSentence{attributes: attrs})
			}
			return resp, nil
		case "!re":
			resp.sentences = append(resp.sentences, mikrotikSentence{attributes: parseMikrotikAttrs(words[1:])})
		case "!trap":
			attrs := parseMikrotikAttrs(words[1:])
			if msg, ok := attrs["message"]; ok {
				resp.err = msg
			} else {
				resp.err = "unknown error"
			}
			// Continue reading until !done
		case "!fatal":
			attrs := parseMikrotikAttrs(words[1:])
			msg := "fatal error"
			if m, ok := attrs["message"]; ok {
				msg = m
			}
			return nil, fmt.Errorf("fatal: %s", msg)
		}
	}
	return nil, fmt.Errorf("response exceeds %d sentences", maxMikrotikSentences)
}

func (c *mikrotikClient) readSentence() ([]string, error) {
	if tc, ok := c.conn.(net.Conn); ok {
		if err := tc.SetReadDeadline(time.Now().Add(mikrotikReadTimeout)); err != nil {
			return nil, fmt.Errorf("set read deadline: %w", err)
		}
	}
	words := make([]string, 0, 16)
	totalBytes := 0
	for len(words) < maxMikrotikWords {
		word, err := c.readWord()
		if err != nil {
			return nil, err
		}
		if word == "" {
			return words, nil
		}
		totalBytes += len(word)
		if totalBytes > maxMikrotikResponse {
			return nil, fmt.Errorf("sentence exceeds %d bytes", maxMikrotikResponse)
		}
		words = append(words, word)
	}
	return nil, fmt.Errorf("sentence exceeds %d words", maxMikrotikWords)
}

func (c *mikrotikClient) readWord() (string, error) {
	length, err := c.readLength()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	if length > maxMikrotikWordSize {
		return "", fmt.Errorf("word size %d exceeds max %d", length, maxMikrotikWordSize)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return "", fmt.Errorf("read word: %w", err)
	}
	return string(buf), nil
}

func (c *mikrotikClient) readLength() (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(c.conn, first[:]); err != nil {
		return 0, err
	}
	b := first[0]

	if b < 0x80 {
		return int(b), nil
	} else if b < 0xC0 {
		var extra [1]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return int(b&0x3F)<<8 | int(extra[0]), nil
	} else if b < 0xE0 {
		var extra [2]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return checkedMikrotikLength(uint64(b&0x1F)<<16 | uint64(extra[0])<<8 | uint64(extra[1]))
	} else if b < 0xF0 {
		var extra [3]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return checkedMikrotikLength(uint64(b&0x0F)<<24 | uint64(extra[0])<<16 | uint64(extra[1])<<8 | uint64(extra[2]))
	} else {
		var extra [4]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return checkedMikrotikLength(uint64(extra[0])<<24 | uint64(extra[1])<<16 | uint64(extra[2])<<8 | uint64(extra[3]))
	}
}

func checkedMikrotikLength(length uint64) (int, error) {
	maxInt := uint64(^uint(0) >> 1)
	if length > maxInt {
		return 0, fmt.Errorf("word length %d overflows int", length)
	}
	return int(length), nil
}

// encodeLength encodes a RouterOS API length prefix.
func encodeLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x4000:
		return []byte{byte(n>>8) | 0x80, byte(n & 0xFF)}
	case n < 0x200000:
		return []byte{byte(n>>16) | 0xC0, byte(n >> 8 & 0xFF), byte(n & 0xFF)}
	case n < 0x10000000:
		return []byte{byte(n>>24) | 0xE0, byte(n >> 16 & 0xFF), byte(n >> 8 & 0xFF), byte(n & 0xFF)}
	default:
		return []byte{0xF0, byte(n >> 24 & 0xFF), byte(n >> 16 & 0xFF), byte(n >> 8 & 0xFF), byte(n & 0xFF)}
	}
}

// parseMikrotikAttrs parses =key=value words into a map.
func parseMikrotikAttrs(words []string) map[string]string {
	attrs := make(map[string]string)
	for _, w := range words {
		kv, found := strings.CutPrefix(w, "=")
		if !found {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		attrs[k] = v
	}
	return attrs
}

// executeMikrotikJob handles a MikroTik API job including backup-via-SSH.
func executeMikrotikJob(ctx context.Context, job *pb.AgentJob, resultCh chan<- *pb.MikrotikResult) {
	dev := job.MikrotikDevice
	if dev == nil {
		slog.Error("job missing mikrotik device", "job_id", job.JobId)
		sendResult(ctx, resultCh, &pb.MikrotikResult{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Error:     "missing device configuration",
			Timestamp: time.Now().Unix(),
		}, job.JobId)
		return
	}

	timestamp := time.Now().Unix()

	// Backup jobs use SSH
	if strings.HasPrefix(job.JobId, "backup:") {
		executeMikrotikBackupViaSSH(ctx, job, dev, resultCh, timestamp)
		return
	}

	slog.Debug("executing mikrotik job", "job_id", job.JobId, "device", dev.Ip, "port", dev.Port, "ssl", dev.UseSsl)

	client, err := mikrotikDial(ctx, dev.Ip, dev.Port, dev.Username, dev.Password, dev.UseSsl)
	if err != nil {
		sendResult(ctx, resultCh, &pb.MikrotikResult{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Error:     fmt.Sprintf("connection failed: %v", err),
			Timestamp: timestamp,
		}, job.JobId)
		return
	}
	defer func() { _ = client.close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = client.conn.Close() })
	defer stopCancel()

	var allSentences []*pb.MikrotikSentence
	var errorMessage string

	for _, cmd := range job.MikrotikCommands {
		slog.Debug("executing mikrotik command", "command", cmd.Command, "args", len(cmd.Args))

		resp, err := client.execute(cmd.Command, cmd.Args)
		if err != nil {
			errorMessage = fmt.Sprintf("command '%s' failed: %v", cmd.Command, err)
			slog.Error("mikrotik command failed", "device", job.DeviceId, "error", errorMessage)
			break
		}
		if resp.err != "" {
			errorMessage = fmt.Sprintf("command '%s' error: %s", cmd.Command, resp.err)
			slog.Error("mikrotik command error", "device", job.DeviceId, "error", errorMessage)
			break
		}

		for _, s := range resp.sentences {
			allSentences = append(allSentences, &pb.MikrotikSentence{Attributes: s.attributes})
		}
	}

	sendResult(ctx, resultCh, &pb.MikrotikResult{
		DeviceId:  job.DeviceId,
		JobId:     job.JobId,
		Sentences: allSentences,
		Error:     errorMessage,
		Timestamp: timestamp,
	}, job.JobId)
}

// executeMikrotikBackupViaSSH runs /export compact over SSH.
func executeMikrotikBackupViaSSH(ctx context.Context, job *pb.AgentJob, dev *pb.MikrotikDevice, resultCh chan<- *pb.MikrotikResult, timestamp int64) {
	slog.Debug("executing backup via ssh", "device", job.DeviceId, "ip", dev.Ip, "ssh_port", dev.SshPort)
	if dev.SshPort > 65535 {
		sendResult(ctx, resultCh, &pb.MikrotikResult{
			DeviceId: job.DeviceId, JobId: job.JobId,
			Error: fmt.Sprintf("invalid SSH port %d", dev.SshPort), Timestamp: timestamp,
		}, job.JobId)
		return
	}

	config, err := sshBackup(ctx, dev.Ip, uint16(dev.SshPort), dev.Username, dev.Password)
	if err != nil {
		sendResult(ctx, resultCh, &pb.MikrotikResult{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Error:     fmt.Sprintf("SSH backup failed: %v", err),
			Timestamp: timestamp,
		}, job.JobId)
		return
	}

	sendResult(ctx, resultCh, &pb.MikrotikResult{
		DeviceId: job.DeviceId,
		JobId:    job.JobId,
		Sentences: []*pb.MikrotikSentence{
			{Attributes: map[string]string{"config": config}},
		},
		Timestamp: timestamp,
	}, job.JobId)
}
