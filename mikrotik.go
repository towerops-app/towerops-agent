package main

import (
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
	mikrotikConnTimeout = 30 * time.Second
	mikrotikReadTimeout = 30 * time.Second
)

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
func mikrotikConnect(ip string, port uint32, username, password string, useSSL bool) (*mikrotikClient, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error

	if useSSL {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: mikrotikConnTimeout},
			Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}
		conn, err = dialer.DialContext(nil, "tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, mikrotikConnTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}

	c := &mikrotikClient{conn: conn}

	// Authenticate
	resp, err := c.execute("/login", map[string]string{"name": username, "password": password})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if resp.err != "" {
		conn.Close()
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
	c.execute("/quit", nil) // best-effort
	return c.conn.Close()
}

func (c *mikrotikClient) writeSentence(words []string) error {
	var buf []byte
	for _, w := range words {
		buf = append(buf, encodeLength(len(w))...)
		buf = append(buf, w...)
	}
	buf = append(buf, 0) // empty word terminates sentence

	_, err := c.conn.Write(buf)
	return err
}

func (c *mikrotikClient) readResponse() (*mikrotikResponse, error) {
	resp := &mikrotikResponse{}

	for {
		words, err := c.readSentence()
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
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
}

func (c *mikrotikClient) readSentence() ([]string, error) {
	var words []string
	for {
		if tc, ok := c.conn.(net.Conn); ok {
			tc.SetReadDeadline(time.Now().Add(mikrotikReadTimeout))
		}
		word, err := c.readWord()
		if err != nil {
			return nil, err
		}
		if word == "" {
			break
		}
		words = append(words, word)
	}
	return words, nil
}

func (c *mikrotikClient) readWord() (string, error) {
	length, err := c.readLength()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
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
		return int(b&0x1F)<<16 | int(extra[0])<<8 | int(extra[1]), nil
	} else if b < 0xF0 {
		var extra [3]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return int(b&0x0F)<<24 | int(extra[0])<<16 | int(extra[1])<<8 | int(extra[2]), nil
	} else {
		var extra [4]byte
		if _, err := io.ReadFull(c.conn, extra[:]); err != nil {
			return 0, err
		}
		return int(extra[0])<<24 | int(extra[1])<<16 | int(extra[2])<<8 | int(extra[3]), nil
	}
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
func executeMikrotikJob(job *pb.AgentJob, resultCh chan<- *pb.MikrotikResult) {
	dev := job.MikrotikDevice
	if dev == nil {
		slog.Error("job missing mikrotik device", "job_id", job.JobId)
		return
	}

	timestamp := time.Now().Unix()

	// Backup jobs use SSH
	if strings.HasPrefix(job.JobId, "backup:") {
		executeMikrotikBackupViaSSH(job, dev, resultCh, timestamp)
		return
	}

	slog.Debug("executing mikrotik job", "job_id", job.JobId, "device", dev.Ip, "port", dev.Port, "ssl", dev.UseSsl)

	client, err := mikrotikConnect(dev.Ip, dev.Port, dev.Username, dev.Password, dev.UseSsl)
	if err != nil {
		resultCh <- &pb.MikrotikResult{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Error:     fmt.Sprintf("connection failed: %v", err),
			Timestamp: timestamp,
		}
		return
	}
	defer client.close()

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

	resultCh <- &pb.MikrotikResult{
		DeviceId:  job.DeviceId,
		JobId:     job.JobId,
		Sentences: allSentences,
		Error:     errorMessage,
		Timestamp: timestamp,
	}
}

// executeMikrotikBackupViaSSH runs /export compact over SSH.
func executeMikrotikBackupViaSSH(job *pb.AgentJob, dev *pb.MikrotikDevice, resultCh chan<- *pb.MikrotikResult, timestamp int64) {
	slog.Debug("executing backup via ssh", "device", job.DeviceId, "ip", dev.Ip, "ssh_port", dev.SshPort)

	config, err := executeMikrotikBackup(dev.Ip, uint16(dev.SshPort), dev.Username, dev.Password)
	if err != nil {
		resultCh <- &pb.MikrotikResult{
			DeviceId:  job.DeviceId,
			JobId:     job.JobId,
			Error:     fmt.Sprintf("SSH backup failed: %v", err),
			Timestamp: timestamp,
		}
		return
	}

	resultCh <- &pb.MikrotikResult{
		DeviceId: job.DeviceId,
		JobId:    job.JobId,
		Sentences: []*pb.MikrotikSentence{
			{Attributes: map[string]string{"config": config}},
		},
		Timestamp: timestamp,
	}
}
