// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

// errConfigBackupHostKeyMismatch tags a host key verification failure so the
// job can report HOST_KEY_MISMATCH with the observed fingerprint.
var errConfigBackupHostKeyMismatch = errors.New("config backup host key mismatch")

const (
	configBackupDefaultTimeoutMs = 120_000
	configBackupDialTimeout      = 15 * time.Second
	maxConfigBackupDetailLen     = 300
	defaultMaxConfigBytes        = 16 << 20
)

// configBackupVendor is implemented per vendor. Both methods return a result
// (never an error): failures are encoded as ErrorCode/ErrorDetail.
type configBackupVendor interface {
	Probe(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult
	Backup(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult
}

var configBackupVendors = map[string]configBackupVendor{"mikrotik": mikrotikBackupVendor{}}

// executeConfigBackupJob runs one CONFIG_BACKUP job: dial, probe or export,
// and queue the result unless the session is ending.
func executeConfigBackupJob(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	started := time.Now()
	finish := func(result *pb.ConfigBackupResult) {
		result.DurationMs = uint32(time.Since(started).Milliseconds())
		result.Timestamp = time.Now().Unix()
		sendResult(ctx, out, "config_backup_result", result, job.JobId)
	}
	fail := func(code pb.ConfigBackupErrorCode, detail string) {
		finish(&pb.ConfigBackupResult{
			DeviceId:    job.DeviceId,
			JobId:       job.JobId,
			ErrorCode:   code,
			ErrorDetail: detail,
		})
	}

	cb := job.ConfigBackup
	if cb == nil {
		fail(pb.ConfigBackupErrorCode_INTERNAL, "config backup job missing payload")
		return
	}

	timeout := time.Duration(cb.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = configBackupDefaultTimeoutMs * time.Millisecond
	}
	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if ctx.Err() != nil {
		return
	}

	client, fingerprint, err := configBackupDial(jobCtx, job)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		code, detail := classifyConfigBackupError(err, job)
		result := &pb.ConfigBackupResult{
			DeviceId:           job.DeviceId,
			JobId:              job.JobId,
			ErrorCode:          code,
			ErrorDetail:        detail,
			HostKeyFingerprint: fingerprint,
		}
		finish(result)
		return
	}
	defer func() { _ = client.Close() }()
	stopCancel := context.AfterFunc(jobCtx, func() { _ = client.Close() })
	defer stopCancel()

	vendor, ok := configBackupVendors[strings.ToLower(strings.TrimSpace(cb.Vendor))]
	if !ok {
		fail(pb.ConfigBackupErrorCode_UNSUPPORTED_VENDOR, "unsupported vendor: "+cb.Vendor)
		return
	}

	var result *pb.ConfigBackupResult
	if cb.Mode == pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE {
		result = vendor.Probe(jobCtx, client, cb, job.JobId, job.DeviceId)
	} else {
		result = vendor.Backup(jobCtx, client, cb, job.JobId, job.DeviceId)
	}
	if ctx.Err() != nil {
		return
	}
	if result.HostKeyFingerprint == "" {
		result.HostKeyFingerprint = fingerprint
	}
	finish(result)
}

// configBackupDial connects to the target and returns the client plus the
// observed host key fingerprint (set whenever a handshake reached the
// callback, including on mismatch).
func configBackupDial(ctx context.Context, job *pb.AgentJob) (*ssh.Client, string, error) {
	cb := job.ConfigBackup
	expected := strings.TrimSpace(cb.ExpectedHostKeyFingerprint)
	var observed string
	config := &ssh.ClientConfig{
		User:            cb.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cb.Password)},
		HostKeyCallback: configBackupHostKeyCallback(expected, &observed),
		Timeout:         configBackupDialTimeout,
	}

	port := cb.SshPort
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(cb.Host, strconv.Itoa(int(port)))
	conn, err := sshDial(ctx, "tcp", addr, config)
	if err != nil {
		return nil, observed, err
	}
	return conn, observed, nil
}

// configBackupHostKeyCallback accepts first-use fingerprints, verifies known
// ones, and records the observed fingerprint even when it rejects.
func configBackupHostKeyCallback(expected string, observed *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		*observed = actual
		if expected == "" {
			return nil
		}
		if strings.HasPrefix(expected, "SHA256:") {
			if actual == expected {
				return nil
			}
		} else if fmt.Sprintf("%x", sha256.Sum256(key.Marshal())) == strings.ToLower(expected) {
			return nil
		}
		return fmt.Errorf("%w", errConfigBackupHostKeyMismatch)
	}
}

// classifyConfigBackupError maps a dial/session error to a result code and a
// sanitized one-line detail. The job password is scrubbed defensively even
// though no library error should contain it.
func classifyConfigBackupError(err error, job *pb.AgentJob) (pb.ConfigBackupErrorCode, string) {
	var code pb.ConfigBackupErrorCode
	switch {
	case errors.Is(err, errConfigBackupHostKeyMismatch):
		code = pb.ConfigBackupErrorCode_HOST_KEY_MISMATCH
	case errors.Is(err, context.DeadlineExceeded):
		code = pb.ConfigBackupErrorCode_TIMEOUT
	case isAuthFailure(err):
		code = pb.ConfigBackupErrorCode_AUTH_FAILED
	case isConnRefused(err):
		code = pb.ConfigBackupErrorCode_CONNECTION_REFUSED
	case isUnreachable(err):
		code = pb.ConfigBackupErrorCode_UNREACHABLE
	default:
		code = pb.ConfigBackupErrorCode_INTERNAL
	}

	detail := firstLine(err.Error(), maxConfigBackupDetailLen)
	if pw := job.ConfigBackup.GetPassword(); pw != "" {
		detail = strings.ReplaceAll(detail, pw, "***")
	}
	return code, detail
}

func isAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "ssh: handshake failed") ||
		strings.Contains(msg, "auth fail") ||
		strings.Contains(msg, "permission denied")
}

func isConnRefused(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && strings.Contains(opErr.Err.Error(), "refused")
}

func isUnreachable(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "no route")
}

func firstLine(s string, max int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// mikrotikBackupVendor implements config backups over a RouterOS SSH session.
type mikrotikBackupVendor struct{}

// runSession runs cmd on a fresh session, returning stdout and stderr
// separately. A non-zero exit keeps the captured stdout so callers can
// classify the failure from device output.
func runConfigBackupSession(c *ssh.Client, cmd string) (stdout, stderr []byte, err error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = session.Close() }()

	var outBuf, errBuf bytes.Buffer
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	runErr := session.Run(cmd)
	return outBuf.Bytes(), errBuf.Bytes(), runErr
}

// configBackupError builds a failure result, scrubbing the password.
func configBackupError(job *pb.ConfigBackupJob, jobID, deviceID string, code pb.ConfigBackupErrorCode, detail string) *pb.ConfigBackupResult {
	detail = firstLine(detail, maxConfigBackupDetailLen)
	if job.Password != "" {
		detail = strings.ReplaceAll(detail, job.Password, "***")
	}
	return &pb.ConfigBackupResult{
		DeviceId:    deviceID,
		JobId:       jobID,
		ErrorCode:   code,
		ErrorDetail: detail,
	}
}

// routerOSVersionMajor parses the leading major from a version like "7.15.3
// (stable)"; unparseable output yields 0.
func routerOSVersionMajor(version string) int {
	version = strings.TrimSpace(version)
	end := strings.IndexAny(version, ". \t(")
	if end >= 0 {
		version = version[:end]
	}
	major, _ := strconv.Atoi(version)
	return major
}

// mikrotikExportCommand picks the export variant for the RouterOS major and
// whether secrets may be included.
func mikrotikExportCommand(major int, includeSecrets bool) string {
	if major >= 7 {
		if includeSecrets {
			return "/export show-sensitive"
		}
		return "/export"
	}
	if includeSecrets {
		return "/export"
	}
	return "/export hide-sensitive"
}

func (mikrotikBackupVendor) readVersion(c *ssh.Client) (string, error) {
	out, _, err := runConfigBackupSession(c, ":put [/system resource get version]")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (mikrotikBackupVendor) readIdentity(c *ssh.Client) (string, error) {
	out, _, err := runConfigBackupSession(c, ":put [/system identity get name]")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Probe gathers version, identity, and the login's group policies. It never
// exports, so ConfigGzip stays empty.
func (v mikrotikBackupVendor) Probe(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	result := &pb.ConfigBackupResult{DeviceId: deviceID, JobId: jobID}

	version, err := v.readVersion(c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx), err.Error())
	}
	result.OsVersion = version

	identity, err := v.readIdentity(c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx), err.Error())
	}
	result.Identity = identity

	policyCmd := fmt.Sprintf(":put [/user group get [/user get [find name=\"%s\"] group] policy]", job.Username)
	out, _, err := runConfigBackupSession(c, policyCmd)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx), err.Error())
	}
	for _, p := range strings.Split(strings.TrimSpace(string(out)), ",") {
		if p = strings.TrimSpace(p); p != "" {
			result.UserPolicies = append(result.UserPolicies, p)
		}
	}
	return result
}

// Backup exports the full configuration, classifies device-side failures, and
// gzips the result.
func (v mikrotikBackupVendor) Backup(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	version, err := v.readVersion(c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx), err.Error())
	}

	major := routerOSVersionMajor(version)
	if major == 0 {
		major = 7 // Unparseable version strings are treated as modern RouterOS.
	}

	out, stderr, err := runConfigBackupSession(c, mikrotikExportCommand(major, job.IncludeSecrets))
	combined := string(out)
	if combined == "" {
		combined = string(stderr)
	}
	if err != nil {
		detail := combined
		if detail == "" {
			detail = err.Error()
		}
		if code := classifyExportOutput(combined); code != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			return configBackupError(job, jobID, deviceID, code, detail)
		}
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_EXPORT_FAILED, detail)
	}
	if code := classifyExportOutput(combined); code != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		return configBackupError(job, jobID, deviceID, code, firstLine(combined, maxConfigBackupDetailLen))
	}

	maxBytes := job.MaxConfigBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxConfigBytes
	}
	if uint64(len(out)) > maxBytes {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_TOO_LARGE,
			fmt.Sprintf("export is %d bytes, limit is %d", len(out), maxBytes))
	}

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(out); err != nil {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_INTERNAL, err.Error())
	}
	if err := w.Close(); err != nil {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_INTERNAL, err.Error())
	}

	identity, _ := v.readIdentity(c)

	return &pb.ConfigBackupResult{
		DeviceId:        deviceID,
		JobId:           jobID,
		ConfigGzip:      gz.Bytes(),
		ConfigBytes:     uint64(len(out)),
		OsVersion:       version,
		Model:           parseExportModel(combined),
		Identity:        identity,
		IncludesSecrets: job.IncludeSecrets,
	}
}

// classifyExportOutput maps RouterOS failure text in stdout/stderr to an
// error code, and sanity-checks that an export looks like a real config.
func classifyExportOutput(output string) pb.ConfigBackupErrorCode {
	if strings.TrimSpace(output) == "" {
		return pb.ConfigBackupErrorCode_EXPORT_EMPTY
	}
	head := output
	if i := strings.IndexByte(head, '\n'); i >= 0 {
		head = head[:i]
	}
	lower := strings.ToLower(head)
	if strings.Contains(lower, "failure:") || strings.Contains(lower, "bad command") {
		return pb.ConfigBackupErrorCode_EXPORT_FAILED
	}
	if strings.Contains(lower, "no permission") || strings.Contains(lower, "not enough permissions") {
		return pb.ConfigBackupErrorCode_PERMISSION_DENIED
	}
	hasComment, hasSection := false, false
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			hasComment = true
		}
		if strings.HasPrefix(trimmed, "/") {
			hasSection = true
		}
	}
	if !hasComment && !hasSection {
		return pb.ConfigBackupErrorCode_EXPORT_INCOMPLETE
	}
	return pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK
}

// parseExportModel extracts the model from a "# model = X" header comment.
func parseExportModel(output string) string {
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, "#"); ok {
			if k, v, ok := strings.Cut(strings.TrimSpace(rest), "="); ok &&
				strings.EqualFold(strings.TrimSpace(k), "model") {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// sessionErrCode maps a session failure to TIMEOUT when the job deadline
// fired (the AfterFunc conn close is what aborts the read).
func sessionErrCode(ctx context.Context) pb.ConfigBackupErrorCode {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return pb.ConfigBackupErrorCode_TIMEOUT
	}
	return pb.ConfigBackupErrorCode_EXPORT_FAILED
}
