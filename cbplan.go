// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

const (
	// defaultPlanStepTimeoutMs applies when the plan carries no step timeout.
	defaultPlanStepTimeoutMs = 20_000
	// stepFailureScanLines bounds how much of a command's output the failure
	// regexes inspect.
	stepFailureScanLines = 20
)

// permissionDeniedRes are the permission-denied phrases a command's output
// is scanned for — the classic Unimus set: anything matching one of these
// in the first 20 lines of a command's output is permission text, which
// triggers the step's fallbacks and, at exhaustion, PERMISSION_DENIED.
var permissionDeniedRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)permission denied`),
	regexp.MustCompile(`(?i)access denied`),
	regexp.MustCompile(`(?i)% authorization failed`),
	regexp.MustCompile(`(?i)authentication failed`),
	regexp.MustCompile(`(?i)% password:`),
	regexp.MustCompile(`(?i)% bad secrets`),
	regexp.MustCompile(`(?i)invalid password`),
	regexp.MustCompile(`(?i)% login invalid`),
}

// invalidCommandRe detects device-side rejections of the command itself,
// built from the invalid-command phrases in tmp/unimus.md section 6:
// a qualifier (invalid, incomplete, ambiguous, unrecognized, unsupported,
// unknown) followed by command/input/keyword, "% Invalid input", a '^'
// error marker line, ": not found", "No such file or directory",
// "syntax error" and "expected end of command".
var invalidCommandRe = regexp.MustCompile(`(?i)(?:invalid|incomplete|ambiguous|unrecogni[sz]ed|unsupported|unknown)\b.{0,60}?\b(?:command|input|keyword)\b` +
	`|% ?invalid input` +
	`|command (?:not found|not recognized|not supported)` +
	`|: not found` +
	`|no such file or directory` +
	`|syntax error` +
	`|expected end of command`)

// invalidMarkerLineRe matches a bare '^' error marker line (per-line use).
var invalidMarkerLineRe = regexp.MustCompile(`^[ \t]*\^`)

// planStepFailure classifies why one command was rejected by the device.
type planStepFailure struct {
	code       pb.ConfigBackupErrorCode
	detail     string
	permission bool
}

func (f *planStepFailure) errorResult(cb *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	return configBackupError(cb, jobID, deviceID, f.code, f.detail)
}

// classifyStepOutput scans the first stepFailureScanLines of a command's
// output for permission-denied and invalid-command text. stderr is scanned
// too: exec-channel failures land there.
func classifyStepOutput(stdout, stderr string) *planStepFailure {
	if f := scanFailureLines(stdout); f != nil {
		return f
	}
	return scanFailureLines(stderr)
}

func scanFailureLines(output string) *planStepFailure {
	scanned := 0
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		scanned++
		if scanned > stepFailureScanLines {
			return nil
		}
		for _, re := range permissionDeniedRes {
			if re.MatchString(trimmed) {
				return &planStepFailure{
					code:       pb.ConfigBackupErrorCode_PERMISSION_DENIED,
					detail:     trimmed,
					permission: true,
				}
			}
		}
		if invalidCommandRe.MatchString(trimmed) || invalidMarkerLineRe.MatchString(trimmed) {
			return &planStepFailure{
				code:   pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED,
				detail: trimmed,
			}
		}
	}
	return nil
}

// planRunner carries the state shared by every step of one plan job.
type planRunner struct {
	client   *ssh.Client
	cb       *pb.ConfigBackupJob
	jobID    string
	deviceID string

	maxBytes    uint64
	stepTimeout time.Duration
	pagers      []pagerPattern

	shared   *boundedBuffer // the job's total output, headers included
	overflow bool
	failed   bool

	headersWanted bool // section headers written when >1 included labelled step
}

func newPlanRunner(ctx context.Context, client *ssh.Client, cb *pb.ConfigBackupJob, jobID, deviceID string) *planRunner {
	r := &planRunner{
		client:   client,
		cb:       cb,
		jobID:    jobID,
		deviceID: deviceID,
	}
	r.maxBytes = cb.GetMaxConfigBytes()
	if r.maxBytes == 0 {
		r.maxBytes = defaultMaxConfigBytes
	}
	stepMs := cb.GetPlan().GetStepTimeoutMs()
	if stepMs == 0 {
		stepMs = defaultPlanStepTimeoutMs
	}
	r.stepTimeout = time.Duration(stepMs) * time.Millisecond
	r.pagers = builtinPagerPatterns()
	for _, expr := range cb.GetPlan().GetPagerPatterns() {
		re, err := regexp.Compile(expr)
		if err != nil {
			slog.Debug("plan pager pattern ignored", "pattern", expr, "error", err)
			continue
		}
		r.pagers = append(r.pagers, pagerPattern{re: re, answer: " "})
	}
	r.shared = &boundedBuffer{limit: r.maxBytes, onOverflow: func() { r.overflow = true }}
	return r
}

// stepContext bounds one step; deriving from the job context means the job
// deadline always wins, and the dispatcher's AfterFunc conn close unblocks
// a collection stuck in a read.
func (r *planRunner) stepContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.stepTimeout)
}

// include appends one step's output, preceded by its section header when
// the plan carries more than one included labelled step. Headers count
// toward the job's size limit. boundedBuffer.Write never fails, but the
// error is acknowledged for the errcheck gate.
func (r *planRunner) include(section, text string) {
	if r.failed {
		return
	}
	if r.headersWanted && section != "" {
		_, _ = r.shared.Write([]byte("# ---- " + section + " ----\n"))
	}
	_, _ = r.shared.Write([]byte(text))
	if r.overflow {
		r.failed = true
	}
}

// runPlan executes a plan-driven backup job: exec transport runs each
// command on its own exec channel; shell transport drives one interactive
// PTY session. PROBE authenticates and (on the shell) enters privileged
// mode without running any command step.
func runPlan(ctx context.Context, client *ssh.Client, cb *pb.ConfigBackupJob, jobID, deviceID string) *pb.ConfigBackupResult {
	r := newPlanRunner(ctx, client, cb, jobID, deviceID)
	if cb.GetMode() == pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE {
		return r.probe(ctx)
	}
	var result *pb.ConfigBackupResult
	if cb.GetPlan().GetTransport() == pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_SHELL {
		result = r.runShellPlan(ctx)
	} else {
		result = r.runExecPlan(ctx)
	}
	if result.ErrorCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
		return r.successResult()
	}
	return result
}

// successResult gzips the joined output and fills the plan result fields.
// The common finish closure adds fingerprint, duration and timestamp.
func (r *planRunner) successResult() *pb.ConfigBackupResult {
	if r.failed {
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_TOO_LARGE,
			fmt.Sprintf("backup exceeded the %d byte limit", r.maxBytes))
	}
	var gz bytes.Buffer
	if err := gzipTo(&gz, r.shared.Bytes()); err != nil {
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_INTERNAL, err.Error())
	}
	return &pb.ConfigBackupResult{
		DeviceId:        r.deviceID,
		JobId:           r.jobID,
		ConfigGzip:      gz.Bytes(),
		ConfigBytes:     uint64(len(r.shared.Bytes())),
		IncludesSecrets: true, // CLI output carries whatever secrets the device prints
	}
}

// probe implements PROBE mode for plan jobs: connect (done by the caller),
// learn the prompt on the shell transport and run any privileged step. No
// command step runs. The prompt's host part is reported as identity.
func (r *planRunner) probe(ctx context.Context) *pb.ConfigBackupResult {
	if r.cb.GetPlan().GetTransport() != pb.ConfigBackupTransport_CONFIG_BACKUP_TRANSPORT_SHELL {
		// Exec transport has no prompt to learn; the authenticated
		// connection itself is the probe.
		return &pb.ConfigBackupResult{DeviceId: r.deviceID, JobId: r.jobID}
	}
	sess, err := newShellSession(r.client, r.maxBytes, r.pagers)
	if err != nil {
		return configBackupError(r.cb, r.jobID, r.deviceID, sessionErrCode(ctx, err), err.Error())
	}
	defer sess.close()
	ctx, cancel := r.stepContext(ctx)
	defer cancel()
	prompt, err := sess.learnPrompt(ctx)
	if err != nil {
		return configBackupError(r.cb, r.jobID, r.deviceID, sessionErrCode(ctx, err), err.Error())
	}
	for _, step := range r.cb.GetPlan().GetSteps() {
		if step.GetKind() != pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED {
			continue
		}
		prompt, err = sess.runPrivileged(ctx, step, r.cb.GetEnablePassword(), prompt)
		if err != nil {
			return r.privilegedFailure(ctx, err)
		}
	}
	return &pb.ConfigBackupResult{DeviceId: r.deviceID, JobId: r.jobID, Identity: prompt.host}
}

// privilegedFailure maps a privileged-mode step failure to ENABLE_FAILED.
func (r *planRunner) privilegedFailure(ctx context.Context, err error) *pb.ConfigBackupResult {
	switch {
	case isEnableFailed(err):
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_ENABLE_FAILED, err.Error())
	case errors.Is(err, errShellClosed):
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_EXPORT_FAILED, err.Error())
	default:
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_TIMEOUT, err.Error())
	}
}

// runExecPlan executes a plan over exec channels: one fresh session per
// command, so fallbacks, failure regexes and sections behave the same on
// both transports.
func (r *planRunner) runExecPlan(ctx context.Context) *pb.ConfigBackupResult {
	plan := r.cb.GetPlan()
	r.headersWanted = countIncludedLabelled(plan) > 1
	for _, step := range plan.GetSteps() {
		if step.GetKind() == pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED {
			continue // privileged mode is a shell-transport concept
		}
		if failure := r.execStep(ctx, step); failure != nil {
			if step.GetIgnoreFailure() {
				continue
			}
			return failure.errorResult(r.cb, r.jobID, r.deviceID)
		}
		if r.failed {
			return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_TOO_LARGE,
				fmt.Sprintf("backup exceeded the %d byte limit", r.maxBytes))
		}
	}
	return &pb.ConfigBackupResult{DeviceId: r.deviceID, JobId: r.jobID}
}

// execStep runs one command step and its fallbacks on exec channels.
func (r *planRunner) execStep(ctx context.Context, step *pb.ConfigBackupStep) *planStepFailure {
	commands := append([]string{step.GetCommand()}, step.GetFallbackCommands()...)
	var lastFailure *planStepFailure
	for _, cmd := range commands {
		stepCtx, cancel := r.stepContext(ctx)
		stdout, stderr, err := runConfigBackupSession(stepCtx, r.client, cmd, r.maxBytes)
		cancel() // a canceled step context reads Canceled; only a fired deadline is a timeout
		if errors.Is(err, errConfigBackupTooLarge) {
			r.failed = true
			return nil
		}
		if failure := classifyStepOutput(string(stdout), string(stderr)); failure != nil {
			lastFailure = failure
			continue
		}
		if errors.Is(stepCtx.Err(), context.DeadlineExceeded) ||
			errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &planStepFailure{
				code:   pb.ConfigBackupErrorCode_TIMEOUT,
				detail: "step timed out running " + cmd,
			}
		}
		if err != nil {
			// A non-zero exit without diagnostic text still counts as a
			// failed command; the fallbacks get their turn.
			detail := strings.TrimSpace(string(stdout))
			if detail == "" {
				detail = err.Error()
			}
			lastFailure = &planStepFailure{code: pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED, detail: detail}
			continue
		}
		if !step.GetExcludeOutput() {
			r.include(step.GetSection(), string(stdout))
		}
		return nil
	}
	return lastFailure
}

// runShellPlan executes a plan over one interactive PTY session.
func (r *planRunner) runShellPlan(ctx context.Context) *pb.ConfigBackupResult {
	sess, err := newShellSession(r.client, r.maxBytes, r.pagers)
	if err != nil {
		return configBackupError(r.cb, r.jobID, r.deviceID, sessionErrCode(ctx, err), err.Error())
	}
	defer sess.close()

	learnCtx, cancel := r.stepContext(ctx)
	prompt, err := sess.learnPrompt(learnCtx)
	cancel()
	if err != nil {
		return r.shellSessionFailure(ctx, err)
	}

	r.headersWanted = countIncludedLabelled(r.cb.GetPlan()) > 1
	for _, step := range r.cb.GetPlan().GetSteps() {
		stepCtx, cancel := r.stepContext(ctx)
		if step.GetKind() == pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED {
			prompt, err = sess.runPrivileged(stepCtx, step, r.cb.GetEnablePassword(), prompt)
			cancel()
			if err != nil {
				return r.privilegedFailure(ctx, err)
			}
			continue
		}
		err = r.shellStep(stepCtx, sess, step, prompt)
		cancel()
		if err != nil {
			if isStepFailure(err) {
				failure := err.(stepFailedError).failure
				if step.GetIgnoreFailure() {
					continue
				}
				return failure.errorResult(r.cb, r.jobID, r.deviceID)
			}
			return r.shellSessionFailure(ctx, err)
		}
		if r.failed {
			return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_TOO_LARGE,
				fmt.Sprintf("backup exceeded the %d byte limit", r.maxBytes))
		}
	}
	return &pb.ConfigBackupResult{DeviceId: r.deviceID, JobId: r.jobID}
}

// shellSessionFailure maps a broken shell session to a result code.
func (r *planRunner) shellSessionFailure(ctx context.Context, err error) *pb.ConfigBackupResult {
	switch {
	case errors.Is(err, errShellClosed):
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_EXPORT_FAILED, err.Error())
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return configBackupError(r.cb, r.jobID, r.deviceID, pb.ConfigBackupErrorCode_TIMEOUT, "device prompt did not return in time")
	default:
		return configBackupError(r.cb, r.jobID, r.deviceID, sessionErrCode(ctx, err), err.Error())
	}
}

// shellStep runs one command step and its fallbacks inside the PTY.
func (r *planRunner) shellStep(stepCtx context.Context, sess *shellSession, step *pb.ConfigBackupStep, prompt *devicePrompt) error {
	commands := append([]string{step.GetCommand()}, step.GetFallbackCommands()...)
	var lastFailure *planStepFailure
	for _, cmd := range commands {
		text, err := sess.collect(stepCtx, cmd, prompt)
		if err != nil {
			return err // session or deadline failure, not a device rejection
		}
		if failure := classifyStepOutput(text, ""); failure != nil {
			lastFailure = failure
			continue
		}
		if !step.GetExcludeOutput() {
			r.include(step.GetSection(), text)
		}
		return nil
	}
	return stepFailedError{failure: lastFailure}
}

// stepFailedError wraps a device-side rejection so callers can distinguish
// it from session failures.
type stepFailedError struct{ failure *planStepFailure }

func (e stepFailedError) Error() string { return e.failure.detail }

func isStepFailure(err error) bool {
	_, ok := err.(stepFailedError)
	return ok
}

// countIncludedLabelled counts the non-excluded steps that carry a section
// label: headers appear only when there is more than one.
func countIncludedLabelled(plan *pb.ConfigBackupPlan) int {
	n := 0
	for _, step := range plan.GetSteps() {
		if step.GetKind() == pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND &&
			!step.GetExcludeOutput() && step.GetSection() != "" {
			n++
		}
	}
	return n
}

// redactConfigSecrets scrubs every credential the job carries — password,
// enable password and any private-key content — replacing each with ***.
// Redaction runs before the detail is shortened to 300 bytes.
func redactConfigSecrets(detail string, cb *pb.ConfigBackupJob) string {
	for _, secret := range []string{cb.GetPassword(), cb.GetEnablePassword()} {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, "***")
		}
	}
	if key := cb.GetPrivateKey(); key != "" {
		// Whole PEM blocks collapse to ***, and any echoed fragment of the
		// key's base64 body — a whole line or part of one — is key content.
		detail = privateKeyBlockRe.ReplaceAllString(detail, "***")
		if body := privateKeyBody(key); body != "" {
			detail = redactKeyFragments(detail, body)
		}
	}
	return detail
}

// keyFragmentLen is the shortest base64 run treated as key content.
const keyFragmentLen = 16

// privateKeyBody joins the base64 payload lines of a PEM key.
func privateKeyBody(key string) string {
	var b strings.Builder
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "Proc-Type") || strings.HasPrefix(line, "DEK-Info") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// redactKeyFragments replaces every run of keyFragmentLen or more
// characters that appears in the key's base64 body with ***. Only the
// first 4 KiB are scanned; the shipped detail is shortened to 300 bytes
// afterwards, so nothing unscanned survives.
func redactKeyFragments(detail, body string) string {
	scan := detail
	if len(scan) > 4096 {
		scan = scan[:4096]
	}
	var b strings.Builder
	b.Grow(len(scan))
	i := 0
	for i < len(scan) {
		if i+keyFragmentLen <= len(scan) && strings.Contains(body, scan[i:i+keyFragmentLen]) {
			end := i + keyFragmentLen
			for end+1 <= len(scan) && strings.Contains(body, scan[i:end+1]) {
				end++
			}
			b.WriteString("***")
			i = end
			continue
		}
		b.WriteByte(scan[i])
		i++
	}
	return b.String()
}

// privateKeyBlockRe matches a PEM private key from its BEGIN line to its
// END line (or end of text, covering truncated keys).
var privateKeyBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
