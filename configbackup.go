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
	"io"
	"log/slog"
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

// errConfigBackupTooLarge tags a session whose output crossed the caller's
// byte cap so the job reports TOO_LARGE instead of the channel-close error.
var errConfigBackupTooLarge = errors.New("config backup output exceeds the byte limit")

const (
	configBackupDefaultTimeoutMs = 120_000
	maxConfigBackupDetailLen     = 300
	defaultMaxConfigBytes        = 16 << 20
	// configBackupStderrCap bounds the stderr copy of any session: failure
	// details are truncated to maxConfigBackupDetailLen anyway.
	configBackupStderrCap = 4 << 10
	// configBackupMetaMaxBytes bounds the short metadata commands (version,
	// identity, group policies); a device emitting more is malfunctioning.
	configBackupMetaMaxBytes = 64 << 10
)

// boundedBuffer buffers at most limit bytes and discards the rest; Write never
// fails so io.Copy keeps draining the channel and the remote cannot stall the
// read loop on a dead writer. onOverflow runs once, on the first byte beyond
// the limit.
type boundedBuffer struct {
	buf        bytes.Buffer
	limit      uint64
	overflow   bool
	onOverflow func()
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	avail := b.limit - uint64(b.buf.Len())
	if uint64(len(p)) > avail {
		// avail <= len(p) < max int, so the conversion cannot overflow.
		_, _ = b.buf.Write(p[:int(avail)])
		if !b.overflow {
			b.overflow = true
			if b.onOverflow != nil {
				b.onOverflow()
			}
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// Bytes returns the retained prefix, at most limit bytes.
func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// configBackupDialTimeout is a var so tests can shrink the dial budget, the
// same way ssh_test.go shrinks sshBackupTimeout.
var configBackupDialTimeout = 15 * time.Second

// configBackupVendor is implemented per vendor. Both methods return a result
// (never an error): failures are encoded as ErrorCode/ErrorDetail.
type configBackupVendor interface {
	Probe(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult
	Backup(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult
}

var configBackupVendors = map[string]configBackupVendor{"mikrotik": mikrotikBackupVendor{}}

// configBackupTimeout resolves the whole-job deadline: the server starts its
// accounting when the job is dispatched, so the budget must cover queueing,
// the jitter delay, the per-target gate, and the SSH work — not just the
// execution. submitJob builds jobCtx from this at dispatch time.
func configBackupTimeout(job *pb.AgentJob) time.Duration {
	timeout := time.Duration(job.ConfigBackup.GetTimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = configBackupDefaultTimeoutMs * time.Millisecond
	}
	return timeout
}

// executeConfigBackupJob runs one CONFIG_BACKUP job without a caller-supplied
// deadline; the timeout then starts at execution. Used by tests.
func executeConfigBackupJob(ctx context.Context, job *pb.AgentJob, out *resultQueue) {
	executeConfigBackupJobCtx(ctx, ctx, job, out)
}

// executeConfigBackupJobCtx runs one CONFIG_BACKUP job: dial, probe or export,
// and queue the result unless the session is ending. sessionCtx reports on the
// agent session and is what results are sent through — a job deadline that has
// already fired must not suppress the TIMEOUT result it produced. jobCtx
// carries the whole-job deadline (dispatch to completion); when it has none it
// is given the configured timeout so a direct call still cannot hang.
func executeConfigBackupJobCtx(sessionCtx, jobCtx context.Context, job *pb.AgentJob, out *resultQueue) {
	started := time.Now()
	var fingerprint string
	finish := func(result *pb.ConfigBackupResult) {
		if result.HostKeyFingerprint == "" {
			result.HostKeyFingerprint = fingerprint
		}
		result.DurationMs = uint32(time.Since(started).Milliseconds())
		result.Timestamp = time.Now().Unix()
		sendResult(sessionCtx, out, "config_backup_result", result, job.JobId)
		slog.Info("config backup finished",
			"job_id", job.JobId,
			"device_id", job.DeviceId,
			"error_code", result.ErrorCode.String(),
			"duration_ms", result.DurationMs,
		)
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

	if _, ok := jobCtx.Deadline(); !ok {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithTimeout(jobCtx, configBackupTimeout(job))
		defer cancel()
	}

	if sessionCtx.Err() != nil {
		return
	}

	client, fp, err := configBackupDial(jobCtx, job)
	fingerprint = fp
	if client != nil {
		defer func() { _ = client.Close() }()
	}
	if sessionCtx.Err() != nil {
		return
	}
	if err != nil {
		code, detail := classifyConfigBackupError(err, job)
		// net.Dialer reports both dial and parent deadlines as dial timeouts.
		// An exhausted whole-job budget must keep its TIMEOUT classification.
		if errors.Is(jobCtx.Err(), context.DeadlineExceeded) {
			code = pb.ConfigBackupErrorCode_TIMEOUT
		}
		result := &pb.ConfigBackupResult{
			DeviceId:    job.DeviceId,
			JobId:       job.JobId,
			ErrorCode:   code,
			ErrorDetail: detail,
		}
		finish(result)
		return
	}
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
	if sessionCtx.Err() != nil {
		return
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
		// Timeout is intentionally unset: sshDial never calls ssh.Dial, so the
		// field would be ignored. The context deadline below is the bound.
	}
	routerOSSSHAlgorithms(config)
	port := cb.SshPort
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(cb.Host, strconv.Itoa(int(port)))
	// TCP connect plus handshake share one dial budget so a filtered port
	// fails fast instead of burning the whole job deadline.
	dialCtx, cancel := context.WithTimeout(ctx, configBackupDialTimeout)
	defer cancel()
	conn, err := sshDial(dialCtx, "tcp", addr, config)
	if err != nil {
		// The AfterFunc conn close that aborts a stalled handshake surfaces as
		// "ssh: handshake failed: …closed", which classifyConfigBackupError
		// would read as AUTH_FAILED. Tag it with the deadline so it reports
		// TIMEOUT instead.
		if dialCtx.Err() != nil {
			err = fmt.Errorf("%w: %w", dialCtx.Err(), err)
		}
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
	case isDialTimeout(err):
		// A TCP connect that hit the dial deadline is a filtered or dead
		// host, not a slow job — report it ahead of the generic deadline
		// check, which Go's *net.OpError also satisfies.
		code = pb.ConfigBackupErrorCode_UNREACHABLE
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

	detail := err.Error()
	if pw := job.ConfigBackup.GetPassword(); pw != "" {
		detail = strings.ReplaceAll(detail, pw, "***")
	}
	return code, firstLine(detail, maxConfigBackupDetailLen)
}

func isAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "auth fail") ||
		strings.Contains(msg, "permission denied")
}

func isConnRefused(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && strings.Contains(opErr.Err.Error(), "refused")
}

// isDialTimeout reports a TCP connect that timed out — *net.OpError with
// Op "dial". On modern Go these also satisfy errors.Is(DeadlineExceeded),
// so callers must check this case first.
func isDialTimeout(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Timeout()
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
	return truncateBytes(strings.ToValidUTF8(s, "\uFFFD"), max)
}

// mikrotikBackupVendor implements config backups over a RouterOS SSH session.
type mikrotikBackupVendor struct{}

// runConfigBackupSession runs cmd on a fresh session, returning stdout and
// stderr separately. stdout is kept only up to maxBytes and stderr only to
// configBackupStderrCap; when stdout crosses the cap the channel is closed to
// abort the stream and the returned error is errConfigBackupTooLarge. A
// non-zero exit keeps the captured stdout so callers can classify the failure
// from device output.
func runConfigBackupSession(ctx context.Context, c *ssh.Client, cmd string, maxBytes uint64) (stdout, stderr []byte, err error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = session.Close() }()

	outBuf := boundedBuffer{
		limit:      maxBytes,
		onOverflow: func() { _ = session.Close() },
	}
	errBuf := boundedBuffer{limit: configBackupStderrCap}
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	runErr := session.Run(cmd)
	// RouterOS 6 closes the exec channel without an exit-status, which
	// surfaces as *ssh.ExitMissingError with the output still delivered.
	// Tolerate it only while the job context is live: a deadline-driven
	// conn.Close produces the same error and must stay an error.
	var exitMissing *ssh.ExitMissingError
	if errors.As(runErr, &exitMissing) && ctx.Err() == nil {
		runErr = nil
	}
	if outBuf.overflow {
		return outBuf.Bytes(), errBuf.Bytes(), errConfigBackupTooLarge
	}
	return outBuf.Bytes(), errBuf.Bytes(), runErr
}

// configBackupError builds a failure result, scrubbing the password.
func configBackupError(job *pb.ConfigBackupJob, jobID, deviceID string, code pb.ConfigBackupErrorCode, detail string) *pb.ConfigBackupResult {
	if job.Password != "" {
		detail = strings.ReplaceAll(detail, job.Password, "***")
	}
	detail = firstLine(detail, maxConfigBackupDetailLen)
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

func (mikrotikBackupVendor) readVersion(ctx context.Context, c *ssh.Client) (string, error) {
	out, err := runConfigBackupMetadata(ctx, c, ":put [/system resource get version]")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(out), "\uFFFD")), nil
}

func (mikrotikBackupVendor) readIdentity(ctx context.Context, c *ssh.Client) (string, error) {
	out, err := runConfigBackupMetadata(ctx, c, ":put [/system identity get name]")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(out), "\uFFFD")), nil
}

// routerOSScriptEscaper escapes the characters that would terminate or expand
// inside a RouterOS double-quoted string. Brackets cannot be escaped there —
// RouterOS evaluates [..] as a command substitution even inside quotes — so
// callers must reject values containing them.
var routerOSScriptEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`$`, `\$`,
)

// routerOSScriptString returns s safe for interpolation inside a RouterOS
// double-quoted string literal, or false when s contains a bracket.
func routerOSScriptString(s string) (string, bool) {
	if strings.ContainsAny(s, "[]") {
		return "", false
	}
	return routerOSScriptEscaper.Replace(s), true
}

// Probe gathers version, identity, and the login's group policies. It never
// exports, so ConfigGzip stays empty.
func (v mikrotikBackupVendor) Probe(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	result := &pb.ConfigBackupResult{DeviceId: deviceID, JobId: jobID}

	version, err := v.readVersion(ctx, c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx, err), err.Error())
	}
	result.OsVersion = version

	identity, err := v.readIdentity(ctx, c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx, err), err.Error())
	}
	result.Identity = identity

	safeUser, ok := routerOSScriptString(job.Username)
	if !ok {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_INTERNAL,
			"username cannot be embedded in a RouterOS script")
	}
	policyCmd := fmt.Sprintf(":put [/user group get [/user get [find name=\"%s\"] group] policy]", safeUser)
	out, err := runConfigBackupMetadata(ctx, c, policyCmd)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx, err), err.Error())
	}
	// RouterOS renders the policy list comma-separated in newer versions and
	// semicolon-separated in older ones; entries prefixed with ! are denied
	// rather than granted, so they are skipped for the missing-policy check.
	for _, p := range strings.FieldsFunc(strings.TrimSpace(strings.ToValidUTF8(string(out), "\uFFFD")), func(r rune) bool {
		return r == ',' || r == ';'
	}) {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "!") {
			continue
		}
		result.UserPolicies = append(result.UserPolicies, p)
	}
	return result
}

// Backup exports the full configuration, classifies device-side failures, and
// gzips the result.
func (v mikrotikBackupVendor) Backup(ctx context.Context, c *ssh.Client, job *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	version, err := v.readVersion(ctx, c)
	if err != nil {
		return configBackupError(job, jobID, deviceID, sessionErrCode(ctx, err), err.Error())
	}

	major := routerOSVersionMajor(version)
	if major == 0 {
		major = 7 // Unparseable version strings are treated as modern RouterOS.
	}

	maxBytes := job.MaxConfigBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxConfigBytes
	}
	out, stderr, err := runConfigBackupSession(ctx, c, mikrotikExportCommand(major, job.IncludeSecrets), maxBytes)
	if errors.Is(err, errConfigBackupTooLarge) {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_TOO_LARGE,
			fmt.Sprintf("export exceeded the %d byte limit", maxBytes))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_TIMEOUT, ctx.Err().Error())
	}
	// Stderr can report an export failure after stdout has already emitted
	// configuration. Only explicit failure text overrides stdout validation.
	if failure := routerOSCommandFailure(string(stderr)); failure != nil {
		return configBackupError(job, jobID, deviceID, failure.code, failure.detail)
	}
	combined := string(out)
	if combined == "" {
		combined = string(stderr)
	}
	if failure := routerOSCommandFailure(combined); failure != nil {
		return configBackupError(job, jobID, deviceID, failure.code, failure.detail)
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
		return configBackupError(job, jobID, deviceID, code, combined)
	}

	var gz bytes.Buffer
	if err := gzipTo(&gz, out); err != nil {
		return configBackupError(job, jobID, deviceID, pb.ConfigBackupErrorCode_INTERNAL, err.Error())
	}

	identity, _ := v.readIdentity(ctx, c)

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

// gzipTo writes gzip-compressed data to dst. Declared as a var so tests can
// inject writer failures at the call site.
var gzipTo = func(dst io.Writer, data []byte) error {
	w := gzip.NewWriter(dst)
	if _, err := w.Write(data); err != nil {
		return err
	}
	return w.Close()
}

// classifyExportOutput maps RouterOS failure text in stdout/stderr to an
// error code, and sanity-checks that an export looks like a real config.
func classifyExportOutput(output string) pb.ConfigBackupErrorCode {
	if strings.TrimSpace(output) == "" {
		return pb.ConfigBackupErrorCode_EXPORT_EMPTY
	}
	if failure := routerOSCommandFailure(output); failure != nil {
		return failure.code
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

// RouterOS can report a command failure with a successful SSH exit status.
// Only diagnostic lines qualify; comments and configuration values may
// legitimately contain the same phrases.
type configBackupDeviceError struct {
	code   pb.ConfigBackupErrorCode
	detail string
}

func (e *configBackupDeviceError) Error() string { return e.detail }

func routerOSCommandFailure(output string) *configBackupDeviceError {
	for line := range strings.Lines(output) {
		detail := strings.TrimSpace(line)
		lower := strings.ToLower(detail)
		if strings.HasPrefix(lower, "failure:") || strings.HasPrefix(lower, "bad command") ||
			strings.HasPrefix(lower, "no permission") || strings.HasPrefix(lower, "not enough permissions") {
			code := pb.ConfigBackupErrorCode_EXPORT_FAILED
			if strings.Contains(lower, "no permission") || strings.Contains(lower, "not enough permissions") {
				code = pb.ConfigBackupErrorCode_PERMISSION_DENIED
			}
			return &configBackupDeviceError{code: code, detail: detail}
		}
	}
	return nil
}

func runConfigBackupMetadata(ctx context.Context, c *ssh.Client, cmd string) ([]byte, error) {
	out, stderr, err := runConfigBackupSession(ctx, c, cmd, configBackupMetaMaxBytes)
	if err != nil {
		return nil, err
	}
	if failure := routerOSCommandFailure(string(stderr)); failure != nil {
		return nil, failure
	}
	if failure := routerOSCommandFailure(string(out)); failure != nil {
		return nil, failure
	}
	return out, nil
}

// parseExportModel extracts the model from a "# model = X" header comment.
func parseExportModel(output string) string {
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, "#"); ok {
			if k, v, ok := strings.Cut(strings.TrimSpace(rest), "="); ok &&
				strings.EqualFold(strings.TrimSpace(k), "model") {
				return strings.TrimSpace(strings.ToValidUTF8(v, "\uFFFD"))
			}
		}
	}
	return ""
}

// sessionErrCode maps a session failure to a result code: TOO_LARGE when the
// output cap fired, TIMEOUT when the job deadline fired (the AfterFunc conn
// close is what aborts the read), EXPORT_FAILED otherwise.
func sessionErrCode(ctx context.Context, err error) pb.ConfigBackupErrorCode {
	if errors.Is(err, errConfigBackupTooLarge) {
		return pb.ConfigBackupErrorCode_TOO_LARGE
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return pb.ConfigBackupErrorCode_TIMEOUT
	}
	var failure *configBackupDeviceError
	if errors.As(err, &failure) {
		return failure.code
	}
	return pb.ConfigBackupErrorCode_EXPORT_FAILED
}
