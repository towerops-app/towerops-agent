// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
)

const (
	mikrotikConnTimeout  = 30 * time.Second
	mikrotikReadTimeout  = 30 * time.Second
	mikrotikWriteTimeout = 30 * time.Second
	mikrotikCloseTimeout = 2 * time.Second
	maxMikrotikWordSize  = 10 << 20 // 10 MB
	maxMikrotikResponse  = 16 << 20 // 16 MB aggregate decoded response
	maxMikrotikWords     = 10000
	maxMikrotikSentences = 10000
	// maxMikrotikFailureLen bounds a rejected command's device message.
	maxMikrotikFailureLen = 300
	// mikrotikCommandAttr tags each returned row with the command that
	// produced it. RouterOS attribute names never start with "__".
	mikrotikCommandAttr = "__command"
)

var mikrotikDial = mikrotikConnect

// mikrotikClient is a RouterOS binary API client.
type mikrotikClient struct {
	conn io.ReadWriteCloser
	// password is scrubbed from every device message before it leaves the client.
	password string
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
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
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
	} else {
		dialer := net.Dialer{Timeout: mikrotikConnTimeout}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}

	c := &mikrotikClient{conn: conn, password: password}
	if err := c.open(ctx, addr, username); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// open pins the TLS certificate and logs in. The caller closes the
// connection on any error.
func (c *mikrotikClient) open(ctx context.Context, addr, username string) error {
	if tlsConn, ok := c.conn.(*tls.Conn); ok && len(tlsConn.ConnectionState().PeerCertificates) > 0 {
		fp := tlsCertFingerprint(tlsConn.ConnectionState().PeerCertificates[0])
		if err := getHostKeyStore().verify("tls:"+addr, fp); err != nil {
			return fmt.Errorf("TLS TOFU verification failed for %s: %w", addr, err)
		}
	}

	// Login sentences can stall for mikrotikReadTimeout each; closing the conn
	// on ctx cancellation aborts a wedged login instead of pinning the worker.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	defer stopCancel()

	resp, err := c.execute("/login", map[string]string{"name": username, "password": c.password})
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if challenge := mikrotikLoginChallenge(resp); challenge != "" {
		response, err := legacyMikrotikLoginResponse(c.password, challenge)
		if err != nil {
			return fmt.Errorf("auth challenge: %w", err)
		}
		resp, err = c.execute("/login", map[string]string{"name": username, "response": response})
		if err != nil {
			return fmt.Errorf("auth challenge: %w", err)
		}
	}
	if resp.err != "" {
		// readResponse already scrubbed and bounded the device's message.
		return fmt.Errorf("auth failed: %s", resp.err)
	}
	return nil
}

func mikrotikLoginChallenge(resp *mikrotikResponse) string {
	for _, sentence := range resp.sentences {
		if challenge := sentence.attributes["ret"]; challenge != "" {
			return challenge
		}
	}
	return ""
}

func legacyMikrotikLoginResponse(password, challenge string) (string, error) {
	challengeBytes, err := hex.DecodeString(challenge)
	if err != nil {
		return "", fmt.Errorf("invalid challenge: %w", err)
	}
	payload := make([]byte, 1, 1+len(password)+len(challengeBytes))
	payload = append(payload, password...)
	payload = append(payload, challengeBytes...)
	// #nosec G501 -- RouterOS before 6.43 requires MD5 for its wire protocol.
	digest := md5.Sum(payload)
	return "00" + hex.EncodeToString(digest[:]), nil
}

// execute sends a command and reads the full response. Args are emitted in
// sorted key order so the sentence is deterministic despite random map
// iteration, except that "?#" query-stack operator keys (?#|, ?#!, ...) are
// emitted after every other key: RouterOS applies an operator to the query
// words already pushed, and "?#" sorts before every "?name". A map cannot
// express arbitrary query order, so callers needing a specific sequence (e.g.
// an operator between particular operands) must use cmd.Words instead.
func (c *mikrotikClient) execute(command string, args map[string]string) (*mikrotikResponse, error) {
	words := []string{command}
	for _, k := range sortedMikrotikArgKeys(args) {
		v := args[k]
		switch {
		case strings.HasPrefix(k, "?#"):
			// Stack operations are part of the query word, not a value.
			words = append(words, k+v)
		case strings.HasPrefix(k, "?") || k == ".tag":
			words = append(words, k+"="+v)
		default:
			// .proplist is a command attribute; only .tag is an API attribute.
			words = append(words, "="+k+"="+v)
		}
	}

	return c.executeWords(words)
}

// sortedMikrotikArgKeys returns args' keys sorted, with "?#" query operator
// keys moved after all other keys (still sorted among themselves) so they
// follow the operands they combine.
func sortedMikrotikArgKeys(args map[string]string) []string {
	return slices.SortedFunc(maps.Keys(args), compareMikrotikArgKeys)
}

// compareMikrotikArgKeys orders "?#" operator keys after every other key and
// sorts lexically within each group.
func compareMikrotikArgKeys(a, b string) int {
	aOp, bOp := strings.HasPrefix(a, "?#"), strings.HasPrefix(b, "?#")
	if aOp != bOp {
		if aOp {
			return 1
		}
		return -1
	}
	return strings.Compare(a, b)
}

func (c *mikrotikClient) executeWords(words []string) (*mikrotikResponse, error) {
	// A zero-length word is the end-of-sentence marker on the wire, so an
	// empty command or an empty word would split the sentence in two and
	// make the next command on the connection read the stale reply. Reject
	// both before anything is written.
	if len(words) == 0 || words[0] == "" {
		return nil, fmt.Errorf("empty RouterOS command")
	}
	for i, w := range words[1:] {
		if w == "" {
			return nil, fmt.Errorf("empty RouterOS API word at index %d", i+1)
		}
	}
	if conn, ok := c.conn.(net.Conn); ok {
		if err := conn.SetWriteDeadline(time.Now().Add(mikrotikWriteTimeout)); err != nil {
			return nil, fmt.Errorf("set write deadline: %w", err)
		}
	}
	if err := c.writeSentence(words); err != nil {
		return nil, err
	}

	return c.readResponse()
}

// close sends /quit without reading the reply. RouterOS answers immediately,
// but waiting for a full response under mikrotikReadTimeout let a wedged
// device pin this worker for 30s per job; the write deadline keeps a device
// that stopped reading from pinning it indefinitely instead.
func (c *mikrotikClient) close() error {
	if conn, ok := c.conn.(net.Conn); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(mikrotikCloseTimeout))
	}
	_ = c.writeSentence([]string{"/quit"}) // best-effort
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
	// Bound the complete reply. Renewing this deadline for every sentence
	// lets a device retain a worker for hours by trickling !re sentences.
	if err := c.setReadDeadline(); err != nil {
		return nil, err
	}
	resp := &mikrotikResponse{}
	totalBytes := 0

	for sentenceCount := 0; sentenceCount < maxMikrotikSentences; sentenceCount++ {
		words, err := c.readSentenceWords()
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		for _, word := range words {
			totalBytes += len(word)
		}
		if totalBytes > maxMikrotikResponse {
			return c.discardResponse(fmt.Sprintf("response exceeds %d bytes", maxMikrotikResponse), words)
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
			resp.err = c.deviceMessage(words, "unknown error")
			// Continue reading until !done
		case "!fatal":
			return nil, c.fatalError(words)
		}
	}
	return c.discardResponse(fmt.Sprintf("response exceeds %d sentences", maxMikrotikSentences), nil)
}

// discardResponse drops the rest of an over-budget reply up to its !done, so
// the next command on the connection reads its own reply. words is the
// sentence that crossed the budget, or nil; it may itself end the reply.
// Memory stays bounded by one sentence, and the read deadline readResponse
// set bounds the time. The caller records reason as a command failure.
func (c *mikrotikClient) discardResponse(reason string, words []string) (*mikrotikResponse, error) {
	for {
		if len(words) > 0 {
			switch words[0] {
			case "!done":
				return &mikrotikResponse{err: reason}, nil
			case "!fatal":
				return nil, c.fatalError(words)
			}
		}
		var err error
		if words, err = c.readSentenceWords(); err != nil {
			return nil, fmt.Errorf("%s: %w", reason, err)
		}
	}
}

func (c *mikrotikClient) fatalError(words []string) error {
	return fmt.Errorf("fatal: %s", c.deviceMessage(words, "fatal error"))
}

// deviceMessage returns a !trap or !fatal sentence's message passed through
// sanitizeMikrotikFailure, or fallback when nothing is left.
func (c *mikrotikClient) deviceMessage(words []string, fallback string) string {
	if msg := sanitizeMikrotikFailure(parseMikrotikAttrs(words[1:])["message"], c.password); msg != "" {
		return msg
	}
	return fallback
}

func (c *mikrotikClient) setReadDeadline() error {
	if tc, ok := c.conn.(net.Conn); ok {
		if err := tc.SetReadDeadline(time.Now().Add(mikrotikReadTimeout)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}
	}
	return nil
}

func (c *mikrotikClient) readSentenceWords() ([]string, error) {
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
	// The length prefix is untrusted. io.CopyN reads in chunks of at most
	// 32 KB and the builder grows only as bytes arrive, so a declared 10 MB
	// word that never arrives allocates no more than one chunk.
	var word strings.Builder
	if _, err := io.CopyN(&word, c.conn, int64(length)); err != nil {
		return "", fmt.Errorf("read word: %w", err)
	}
	return word.String(), nil
}

func (c *mikrotikClient) readLength() (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(c.conn, first[:]); err != nil {
		return 0, err
	}
	b := first[0]
	if b >= 0xf8 {
		return 0, fmt.Errorf("unsupported RouterOS control byte 0x%02x", b)
	}

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
		attrs[strings.ToValidUTF8(k, "\uFFFD")] = strings.ToValidUTF8(v, "\uFFFD")
	}
	return attrs
}

func mikrotikError(job *pb.AgentJob, msg string, ts int64) *pb.MikrotikResult {
	return &pb.MikrotikResult{
		DeviceId:  job.DeviceId,
		JobId:     job.JobId,
		Error:     strings.ToValidUTF8(msg, "\uFFFD"),
		Timestamp: ts,
	}
}

// executeMikrotikJob handles a MikroTik API job including backup-via-SSH.
func executeMikrotikJob(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	dev := job.MikrotikDevice
	if dev == nil {
		slog.Error("job missing mikrotik device", "job_id", job.JobId)
		sendResult(ctx, out, "mikrotik_result", mikrotikError(
			job,
			"missing device configuration",
			time.Now().Unix(),
		), job.JobId)
		return
	}

	timestamp := time.Now().Unix()

	// Backup jobs use SSH
	if strings.HasPrefix(job.JobId, "backup:") {
		executeMikrotikBackupViaSSH(ctx, job, dev, out, timestamp)
		return
	}

	port := dev.Port
	if port == 0 {
		if dev.UseSsl {
			port = 8729
		} else {
			port = 8728
		}
	}
	slog.Debug("executing mikrotik job", "job_id", job.JobId, "device", dev.Ip, "port", port, "ssl", dev.UseSsl)

	client, err := mikrotikDial(ctx, dev.Ip, port, dev.Username, dev.Password, dev.UseSsl)
	if err != nil {
		sendResult(ctx, out, "mikrotik_result", mikrotikError(
			job,
			fmt.Sprintf("connection failed: %v", err),
			timestamp,
		), job.JobId)
		return
	}
	defer func() { _ = client.close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = client.conn.Close() })
	defer stopCancel()

	var allSentences []*pb.MikrotikSentence
	var failures []*pb.MikrotikCommandFailure

	for _, cmd := range job.MikrotikCommands {
		slog.Debug("executing mikrotik command", "command", cmd.Command, "args", len(cmd.Args), "words", len(cmd.Words))

		var resp *mikrotikResponse
		var err error
		if len(cmd.Words) > 0 {
			words := make([]string, 1, len(cmd.Words)+1)
			words[0] = cmd.Command
			words = append(words, cmd.Words...)
			resp, err = client.executeWords(words)
		} else {
			resp, err = client.execute(cmd.Command, cmd.Args)
		}
		if err != nil {
			// The connection is no longer usable: end the job, but keep the
			// rows and failures the earlier commands produced.
			errorMessage := fmt.Sprintf("command '%s' failed: %v", cmd.Command, err)
			slog.Error("mikrotik command failed", "device", job.DeviceId, "error", errorMessage)
			result := mikrotikError(job, errorMessage, timestamp)
			result.Sentences = allSentences
			result.CommandFailures = failures
			sendResult(ctx, out, "mikrotik_result", result, job.JobId)
			return
		}
		if resp.err != "" {
			// A !trap or an over-budget reply rejects only this command; the
			// connection stays usable. readResponse already sanitized resp.err.
			slog.Warn("mikrotik command rejected", "device", job.DeviceId, "command", cmd.Command, "error", resp.err)
			failures = append(failures, &pb.MikrotikCommandFailure{Command: cmd.Command, Message: resp.err})
			continue
		}

		for _, s := range resp.sentences {
			s.attributes[mikrotikCommandAttr] = cmd.Command
			allSentences = append(allSentences, &pb.MikrotikSentence{Attributes: s.attributes})
		}
	}

	result := &pb.MikrotikResult{
		DeviceId:        job.DeviceId,
		JobId:           job.JobId,
		Sentences:       allSentences,
		CommandFailures: failures,
		Timestamp:       timestamp,
	}
	if n := len(job.MikrotikCommands); n > 0 && len(failures) == n {
		result.Error = fmt.Sprintf("all %d commands failed", n)
		slog.Error("mikrotik job failed", "device", job.DeviceId, "job", job.JobId, "error", result.Error)
	} else {
		slog.Info("mikrotik job complete", "device", job.DeviceId, "job", job.JobId, "command_failures", len(failures))
	}
	sendResult(ctx, out, "mikrotik_result", result, job.JobId)
}

// sanitizeMikrotikFailure reduces a device's !trap or !fatal message to one
// bounded line with the job password scrubbed, as classifyConfigBackupError
// does.
func sanitizeMikrotikFailure(message, password string) string {
	if password != "" {
		message = strings.ReplaceAll(message, password, "***")
	}
	return firstLine(message, maxMikrotikFailureLen)
}

// executeMikrotikBackupViaSSH runs /export compact over SSH.
func executeMikrotikBackupViaSSH(ctx context.Context, job *pb.AgentJob, dev *pb.MikrotikDevice, out *resultQueue, timestamp int64) {
	slog.Debug("executing backup via ssh", "device", job.DeviceId, "ip", dev.Ip, "ssh_port", dev.SshPort)
	if dev.SshPort > 65535 {
		sendResult(ctx, out, "mikrotik_result", mikrotikError(
			job,
			fmt.Sprintf("invalid SSH port %d", dev.SshPort),
			timestamp,
		), job.JobId)
		return
	}

	port := dev.SshPort
	if port == 0 {
		port = 22
	}

	config, err := sshBackup(ctx, dev.Ip, uint16(port), dev.Username, dev.Password)
	if err != nil {
		sendResult(ctx, out, "mikrotik_result", mikrotikError(
			job,
			fmt.Sprintf("SSH backup failed: %v", err),
			timestamp,
		), job.JobId)
		return
	}

	slog.Info("mikrotik job complete", "device", job.DeviceId, "job", job.JobId)
	sendResult(ctx, out, "mikrotik_result", &pb.MikrotikResult{
		DeviceId: job.DeviceId,
		JobId:    job.JobId,
		Sentences: []*pb.MikrotikSentence{
			{Attributes: map[string]string{"config": strings.ToValidUTF8(config, "\uFFFD")}},
		},
		Timestamp: timestamp,
	}, job.JobId)
}
