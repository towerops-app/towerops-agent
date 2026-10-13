// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

const (
	// shellQuiet is the output-stall window: a pause this long ends the
	// current expect cycle, which is when pager and prompt detection run.
	shellQuiet = 300 * time.Millisecond
	// promptQuiet is the silence window prompt learning waits for after
	// login and around each probe newline.
	promptQuiet = 500 * time.Millisecond
	// pagerWindow is how much output the pager detector inspects.
	pagerWindow = 250
	// shellWriteDeadline bounds the exit write during cleanup.
	shellWriteDeadline = time.Second
)

// errShellClosed reports the SSH session ending underneath a collection.
var errShellClosed = errors.New("shell session closed by the device")

// shellPromptShapeRe accepts a single line as a candidate device prompt:
// 1-80 characters ending in one of the common CLI terminators (or a colon,
// which login and continuation prompts use).
var shellPromptShapeRe = regexp.MustCompile(`^.{1,80}[>#$%\]:]\s*$`)

// shellPasswordPromptRe matches a password request at the end of a line.
var shellPasswordPromptRe = regexp.MustCompile(`(?i)pass(word|code)?:\s*$`)

// shellCounterStripRe removes a trailing -N or :N counter so a learned
// prompt also matches with the counter bumped.
var shellCounterStripRe = regexp.MustCompile(`[-:]\d+$`)

// promptTerminators are the characters a prompt may end in. '#' marks a
// privileged prompt.
const promptTerminators = `>#$%\]`

// devicePrompt is a learned device prompt: the exact line it was learned
// from and a regex that matches it with an optional mode suffix, counter
// and whitespace drift.
type devicePrompt struct {
	line       string
	host       string
	re         *regexp.Regexp
	privileged bool
}

// newDevicePrompt builds a prompt from a line like "sw1(config)#". The
// regex keeps the host literal, allows an optional "(…)" mode suffix and an
// optional -N / :N counter (Unimus INCREMENTAL_PROMPT_REGEX), and ends in
// any terminator with optional surrounding whitespace — so sw1>, sw1# and
// sw1(config-if)# all count as the same prompt.
func newDevicePrompt(line string) (*devicePrompt, error) {
	if strings.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("line %q is not a device prompt", line)
	}
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" || !shellPromptShapeRe.MatchString(trimmed) {
		return nil, fmt.Errorf("line %q is not a device prompt", line)
	}
	term := trimmed[len(trimmed)-1]
	host := strings.TrimRight(trimmed[:len(trimmed)-1], " \t")
	// Strip a trailing (mode) suffix so every mode of the same host
	// matches; the regex below re-adds it as an optional group.
	if strings.HasSuffix(host, ")") {
		if i := strings.LastIndex(host, "("); i > 0 {
			host = host[:i]
		}
	}
	host = strings.TrimRight(shellCounterStripRe.ReplaceAllString(host, ""), " \t")
	if host == "" {
		return nil, fmt.Errorf("prompt %q has no host part", line)
	}
	re := regexp.MustCompile("^" + regexp.QuoteMeta(host) +
		`(?:\([^)]*\))?` + // optional mode suffix
		`(?:-\d+|:\d+)?` + // optional counter
		`\s{0,8}[` + promptTerminators + regexp.QuoteMeta(string(term)) + `]` +
		`\s*$`)
	return &devicePrompt{
		line:       trimmed,
		host:       host,
		re:         re,
		privileged: term == '#',
	}, nil
}

// pagerPattern is one pager marker and the bytes that dismiss it.
type pagerPattern struct {
	re     *regexp.Regexp
	answer string
}

// builtinPagerPatterns are the pager markers devices commonly emit,
// taken from the Unimus driver corpus. (END) is a less(1) screen that is
// dismissed with "q"; everything else takes a space. Each pattern also
// consumes the marker's own line so no empty line is left behind.
func builtinPagerPatterns() []pagerPattern {
	return []pagerPattern{
		{mustCompile(`(?i)-{2,} ?More ?-{2,}(?: or \(q\)uit)?(?:\r?\n)?`), " "}, // --More--, -- More --, --More-- or (q)uit
		{mustCompile(`(?i)<-+ ?More ?-+>(?:\r?\n)?`), " "},                      // <--- More --->
		{mustCompile(`(?i)press any key to continue(?:\r?\n)?`), " "},           // Press any key to continue
		{mustCompile(`(?i)press <space> to continue or <q> to quit(?:\r?\n)?`), " "},
		{mustCompile(`(?i)lines? \d+-\d+(?:/\d+)?(?:\r?\n)?`), " "}, // lines 24-48 (/240)
		{mustCompile(`(?i)\( ?END ?\)(?:\r?\n)?`), "q"},             // less(1) end marker
		{mustCompile(`(?i)-- \[Q quit\|.+\](?:\r?\n)?`), " "},       // RouterOS /export pager
	}
}

func mustCompile(expr string) *regexp.Regexp {
	re, err := regexp.Compile(expr)
	if err != nil {
		panic("config backup: invalid built-in pager regex: " + err.Error())
	}
	return re
}

// shellFilter turns a device's terminal byte stream into plain text: CSI
// and OSC escape sequences are stripped, control bytes other than \n, \r,
// \t and BEL are dropped, \r\n collapses to \n, and a bare \r erases back
// to the line start, which removes spinner and pager-erase artifacts.
// Write is safe for concurrent use — the session's stdout and stderr
// copiers share one filter. out holds complete lines plus the line in
// progress; eraseLine truncates back to the start of that partial line.
type shellFilter struct {
	mu        sync.Mutex
	out       []byte
	lineStart int
	pendingCR bool
	esc       int // 0 none, 1 after ESC, 2 inside CSI, 3 inside OSC
	arrived   chan struct{}
	limit     uint64 // retained-output cap; 0 = unbounded
	overflow  bool
}

func newShellFilter(limit uint64) *shellFilter {
	return &shellFilter{arrived: make(chan struct{}, 1), limit: limit}
}

// overflowed reports that the device pushed past the job's byte cap.
func (f *shellFilter) overflowed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overflow
}

func (f *shellFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	for i := 0; i < len(p); i++ {
		if f.esc != 0 {
			i += f.feedEscape(p[i:]) - 1
			continue
		}
		b := p[i]
		if f.pendingCR {
			f.pendingCR = false
			if b == '\n' {
				f.lineBreak()
				continue // \r\n is one newline
			}
			f.eraseLine() // bare \r erases the line
		}
		switch {
		case b == '\r':
			f.pendingCR = true
		case b == '\n':
			f.lineBreak()
		case b == 0x1b:
			f.esc = 1
		case b == '\t' || b == 0x07:
			f.out = append(f.out, b)
		case b < 0x20 || b == 0x7f:
			// Drop other control bytes.
		default:
			f.out = append(f.out, b)
		}
		if f.limit > 0 && uint64(len(f.out)) > f.limit {
			// Keep the prefix; the job fails with TOO_LARGE.
			f.out = f.out[:f.limit]
			if f.lineStart > len(f.out) {
				f.lineStart = len(f.out)
			}
			f.overflow = true
			break
		}
	}
	f.mu.Unlock()
	select {
	case f.arrived <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (f *shellFilter) lineBreak() {
	f.out = append(f.out, '\n')
	f.lineStart = len(f.out)
}

func (f *shellFilter) eraseLine() {
	f.out = f.out[:f.lineStart]
}

// feedEscape consumes bytes while inside an escape sequence and returns how
// many bytes of p belonged to it. esc carries the state across chunk
// boundaries: 1 after ESC, 2 inside a CSI sequence, 3 inside an OSC string.
func (f *shellFilter) feedEscape(p []byte) int {
	for i := 0; i < len(p); i++ {
		b := p[i]
		switch f.esc {
		case 1: // ESC seen; this byte selects the sequence type
			switch b {
			case '[':
				f.esc = 2
			case ']':
				f.esc = 3
			default:
				f.esc = 0 // two-byte escape sequence
				return i + 1
			}
		case 2: // CSI: parameter bytes, then one final byte in @-~
			if b >= 0x40 && b <= 0x7e {
				f.esc = 0
				return i + 1
			}
		case 3: // OSC: ends at BEL or ESC \
			if b == 0x07 {
				f.esc = 0
				return i + 1
			}
			if b == 0x1b {
				if i+1 < len(p) {
					f.esc = 0
					return i + 2
				}
				f.esc = 1 // the next chunk's first byte closes the sequence
			}
		}
	}
	return len(p) // the whole chunk is part of the sequence
}

// Bytes returns the filtered output.
func (f *shellFilter) Bytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out
}

// shellSession is one interactive PTY session against a device. Output is
// filtered as it arrives; collection waits for prompts, answers pagers and
// strips the echoed command.
type shellSession struct {
	session *ssh.Session
	stdin   io.WriteCloser
	filter  *shellFilter
	pagers  []pagerPattern

	eofC    chan struct{}
	waitErr error
}

// newShellSession opens a vt100 PTY shell with ECHO on and starts the
// output copiers. The retained output is capped at maxBytes: a device
// pushing past the job's size limit fails the job with TOO_LARGE instead
// of growing the buffer without end.
func newShellSession(c *ssh.Client, maxBytes uint64, pagers []pagerPattern) (*shellSession, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	s := &shellSession{session: session, pagers: pagers, filter: newShellFilter(maxBytes)}
	// StdinPipe cannot fail here: the session is fresh, so Stdin is unset
	// and nothing has started. The error is acknowledged for errcheck.
	s.stdin, _ = session.StdinPipe()
	session.Stdout = s.filter
	session.Stderr = s.filter
	if err := session.RequestPty("vt100", 100, 200, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}); err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, err
	}
	s.eofC = make(chan struct{})
	go func() {
		s.waitErr = session.Wait()
		close(s.eofC)
	}()
	return s, nil
}

// send writes bytes to the shell's stdin.
func (s *shellSession) send(data string) error {
	_, err := io.WriteString(s.stdin, data)
	return err
}

type shellEvent int

const (
	shellEvtData shellEvent = iota
	shellEvtQuiet
	shellEvtEOF
	shellEvtDone // context expired
)

// waitOutput blocks until new output arrives, the quiet window elapses, the
// session ends, or ctx expires — whichever comes first.
func (s *shellSession) waitOutput(ctx context.Context, quiet time.Duration) shellEvent {
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case <-s.filter.arrived:
			return shellEvtData
		case <-timer.C:
			return shellEvtQuiet
		case <-s.eofC:
			return shellEvtEOF
		case <-ctx.Done():
			return shellEvtDone
		}
	}
}

// quietRead collects new output until it has been silent for quiet, or ctx
// expires (then err is non-nil). It returns the text gathered during the call.
func (s *shellSession) quietRead(ctx context.Context, quiet time.Duration) (string, error) {
	start := len(s.filter.Bytes())
	for {
		switch s.waitOutput(ctx, quiet) {
		case shellEvtData:
			continue
		case shellEvtQuiet, shellEvtEOF:
			return s.since(start), nil
		case shellEvtDone:
			return s.since(start), ctx.Err()
		}
	}
}

func (s *shellSession) since(start int) string {
	out := s.filter.Bytes()
	if start > len(out) {
		return ""
	}
	return string(out[start:])
}

// learnPrompt discovers the device prompt after login: wait for the login
// banner to go quiet, then send two bare newlines. The prompt is the last
// non-empty line, accepted only when both replies end in that same line and
// the line has a prompt shape — which rejects one-shot banners.
func (s *shellSession) learnPrompt(ctx context.Context) (*devicePrompt, error) {
	if _, err := s.quietRead(ctx, promptQuiet); err != nil {
		return nil, fmt.Errorf("no login banner within the deadline: %w", err)
	}
	if err := s.send("\r"); err != nil {
		return nil, err
	}
	first, err := s.quietRead(ctx, promptQuiet)
	if err != nil {
		return nil, fmt.Errorf("device went quiet before the prompt: %w", err)
	}
	if err := s.send("\r"); err != nil {
		return nil, err
	}
	second, err := s.quietRead(ctx, promptQuiet)
	if err != nil {
		return nil, fmt.Errorf("device went quiet before the prompt: %w", err)
	}
	line := lastNonEmptyLine(first)
	if line == "" || line != lastNonEmptyLine(second) {
		return nil, fmt.Errorf("could not learn the device prompt from %q then %q",
			strings.TrimSpace(first), strings.TrimSpace(second))
	}
	return newDevicePrompt(line)
}

// collect sends cmd and gathers output until the prompt returns. While
// collecting it answers pager markers (each position once) and fails when
// the step's deadline passes without a prompt.
func (s *shellSession) collect(ctx context.Context, cmd string, p *devicePrompt) (string, error) {
	start := len(s.filter.Bytes())
	if err := s.send(cmd + "\r"); err != nil {
		return "", err
	}
	answeredTo := -1 // end offset of the last pager match already answered
	for {
		if s.filter.overflowed() {
			return "", errConfigBackupTooLarge
		}
		switch s.waitOutput(ctx, shellQuiet) {
		case shellEvtData:
			if s.promptReturned(start, p) {
				return s.finishCollect(start, cmd, p), nil
			}
		case shellEvtQuiet:
			if s.answerPager(&answeredTo) {
				continue
			}
			if s.promptReturned(start, p) {
				return s.finishCollect(start, cmd, p), nil
			}
			// Silent without a prompt: keep waiting until the deadline.
		case shellEvtEOF:
			return "", errShellClosed
		case shellEvtDone:
			return "", ctx.Err()
		}
	}
}

// answerPager dismisses the first pager marker whose end position is past
// everything already answered, so each marker position is answered once.
func (s *shellSession) answerPager(answeredTo *int) bool {
	out := s.filter.Bytes()
	windowStart := len(out) - pagerWindow
	if windowStart < 0 {
		windowStart = 0
	}
	window := out[windowStart:]
	bestEnd, bestAnswer := -1, ""
	for _, pg := range s.pagers {
		for _, loc := range pg.re.FindAllIndex(window, -1) {
			end := windowStart + loc[1]
			if end > *answeredTo && (bestEnd < 0 || end < bestEnd) {
				bestEnd, bestAnswer = end, pg.answer
			}
		}
	}
	if bestEnd < 0 {
		return false
	}
	*answeredTo = bestEnd
	_ = s.send(bestAnswer)
	return true
}

// promptReturned reports whether the final line of new output matches the
// learned prompt.
func (s *shellSession) promptReturned(start int, p *devicePrompt) bool {
	out := s.since(start)
	final := lastNonEmptyLine(out)
	return final != "" && p.re.MatchString(final)
}

// finishCollect post-processes one command's raw output: strip the echoed
// command, the returning prompt and any pager markers.
func (s *shellSession) finishCollect(start int, cmd string, p *devicePrompt) string {
	text := s.since(start)
	text = stripEchoedCommand(text, cmd)
	text = stripTrailingPrompt(text, p)
	return stripPagerMarkers(text, s.pagers)
}

// runPrivileged performs a privileged-mode step: skip when the prompt is
// already privileged, otherwise send the command, answer a password prompt
// with the enable password, and re-learn the prompt — which must now be
// privileged. Steps that enter another CLI are covered by the re-learn.
func (s *shellSession) runPrivileged(ctx context.Context, step *pb.ConfigBackupStep, enablePassword string, p *devicePrompt) (*devicePrompt, error) {
	if p.privileged {
		return p, nil // already privileged: no bytes are sent
	}
	if err := s.send(step.GetCommand() + "\r"); err != nil {
		return nil, err
	}
	answered := 0
	for {
		switch s.waitOutput(ctx, shellQuiet) {
		case shellEvtData:
			// A privileged prompt can appear without a stall; wait for the
			// quiet window so multi-line replies settle before judging them.
		case shellEvtQuiet:
			final := lastNonEmptyLine(string(s.filter.Bytes()))
			switch {
			case shellPasswordPromptRe.MatchString(final):
				// A second password request means the first answer was
				// refused — never loop feeding the enable password.
				if enablePassword == "" || answered >= 1 {
					return nil, errEnableFailed("device requested an enable password the job does not carry")
				}
				answered++
				if err := s.send(enablePassword + "\r"); err != nil {
					return nil, err
				}
			case shellPromptShapeRe.MatchString(final):
				next, err := newDevicePrompt(final)
				if err != nil {
					return nil, err
				}
				if !next.privileged {
					return nil, errEnableFailed("prompt %q stayed unprivileged after %q", next.line, step.GetCommand())
				}
				return next, nil
			}
			// Neither password prompt nor prompt shape: keep waiting.
		case shellEvtEOF:
			return nil, errShellClosed
		case shellEvtDone:
			return nil, ctx.Err()
		}
	}
}

// errEnableFailed tags privileged-mode refusals so the plan runner reports
// ENABLE_FAILED.
type enableFailedError struct{ msg string }

func (e enableFailedError) Error() string { return e.msg }

func errEnableFailed(format string, args ...any) error {
	return enableFailedError{msg: fmt.Sprintf(format, args...)}
}

func isEnableFailed(err error) bool {
	var efe enableFailedError
	return errors.As(err, &efe)
}

// close ends the session: exit, then the channel, without waiting for the
// device — some CLIs never close by themselves. A stuck exit write is
// abandoned after shellWriteDeadline; closing the channel unblocks it.
func (s *shellSession) close() {
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = io.WriteString(s.stdin, "exit\r")
	}()
	select {
	case <-written:
	case <-time.After(shellWriteDeadline):
	}
	_ = s.session.Close()
	<-written
}

// stripEchoedCommand removes the leading line(s) carrying the echoed
// command. Comparison is whitespace-insensitive and spans wrapped echoes.
func stripEchoedCommand(text, cmd string) string {
	want := stripAllSpace(cmd)
	if want == "" {
		return text
	}
	lines := strings.SplitAfter(text, "\n")
	limit := len(lines)
	if limit > 8 {
		limit = 8
	}
	var acc strings.Builder
	for i, line := range lines[:limit] {
		acc.WriteString(stripAllSpace(line))
		if strings.Contains(acc.String(), want) {
			return strings.Join(lines[i+1:], "")
		}
	}
	return text
}

// stripTrailingPrompt removes the prompt line that ended the collection.
func stripTrailingPrompt(text string, p *devicePrompt) string {
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return text
	}
	final := lastLine(trimmed)
	if p.re.MatchString(final) {
		return strings.TrimRight(strings.TrimSuffix(trimmed, final), "\n") + "\n"
	}
	return text
}

// stripPagerMarkers removes pager marker text the device left in the stream.
func stripPagerMarkers(text string, pagers []pagerPattern) string {
	for _, pg := range pagers {
		text = pg.re.ReplaceAllString(text, "")
	}
	return text
}

// lastNonEmptyLine returns the last line of text with content, without its
// newline; "" when there is none.
func lastNonEmptyLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimRight(lines[i], "\r")
		if strings.TrimSpace(trimmed) != "" {
			return trimmed
		}
	}
	return ""
}

// lastLine returns text's final line without a trailing newline.
func lastLine(text string) string {
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		return text[i+1:]
	}
	return text
}

// stripAllSpace removes every whitespace rune.
func stripAllSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f', 0x85, 0xA0:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
