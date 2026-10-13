// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

// cbShellClient dials a test SSH server without host key verification.
func cbShellClient(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "backup",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// cbShellSession opens a PTY shell session against the fake device.
func cbShellSession(t *testing.T, addr string, pagers []pagerPattern) *shellSession {
	t.Helper()
	sess, err := newShellSession(cbShellClient(t, addr), defaultMaxConfigBytes, pagers)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// cbLearnPrompt learns the fake device's prompt with a generous deadline.
func cbLearnPrompt(t *testing.T, sess *shellSession) *devicePrompt {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prompt, err := sess.learnPrompt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return prompt
}

// cbCollectOne runs one collect with a generous deadline.
func cbCollectOne(t *testing.T, sess *shellSession, cmd string, prompt *devicePrompt) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	text, err := sess.collect(ctx, cmd, prompt)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestShellFilter(t *testing.T) {
	cases := []struct {
		name  string
		input []string // fed to the filter in separate Write calls
		want  string
	}{
		{"crlf is one newline", []string{"a\r\nb"}, "a\nb"},
		{"bare cr erases the line", []string{"loading...\r         \rdone\n"}, "done\n"},
		{"csi sequences stripped", []string{"\x1b[32mgreen\x1b[0m plain\n"}, "green plain\n"},
		{"osc sequences stripped", []string{"\x1b]0;title\x07prompt\n"}, "prompt\n"},
		{"other control bytes dropped", []string{"a\x01b\x7fc\n"}, "abc\n"},
		{"tab and bell kept", []string{"a\tb\x07\n"}, "a\tb\x07\n"},
		{"csi split across writes", []string{"x\x1b[3", "1m text\n"}, "x text\n"},
		{"osc ends with escape backslash", []string{"a\x1b]0;t\x1b\\b\n"}, "ab\n"},
		{"osc split across writes ends at ESC", []string{"y\x1b]0;ti\x1b", "\\z\n"}, "yz\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newShellFilter(0)
			for _, chunk := range tc.input {
				if _, err := f.Write([]byte(chunk)); err != nil {
					t.Fatal(err)
				}
			}
			if got := string(f.Bytes()); got != tc.want {
				t.Fatalf("filter output = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestShellFilterLimit(t *testing.T) {
	// The retained output is capped: once out crosses the limit it is cut
	// back and overflow is reported. A \r\n landing right at the cap makes
	// the newline itself the byte past the limit, leaving lineStart beyond
	// the truncated end; the clamp keeps it in bounds.
	f := newShellFilter(4)
	if _, err := f.Write([]byte("abcd\r\nxyz")); err != nil {
		t.Fatal(err)
	}
	if !f.overflowed() {
		t.Fatal("overflow not reported")
	}
	if got := string(f.Bytes()); got != "abcd" {
		t.Fatalf("filter output = %q, want the 4-byte prefix", got)
	}
}

func TestDevicePromptRegex(t *testing.T) {
	cases := []struct {
		prompt     string
		privileged bool
		matches    []string
		rejects    []string
	}{
		{prompt: "sw1>", matches: []string{"sw1>", "sw1#", "sw1(config)#", "sw1(config-if)#", "sw1-2>"},
			rejects: []string{"sw2>", "othersw1>", "x sw1>"}},
		{prompt: "admin@edge:~$", matches: []string{"admin@edge:~$"}, rejects: []string{"root@edge:~$"}},
		{prompt: "[admin@MikroTik] >", matches: []string{"[admin@MikroTik] >", "[admin@MikroTik] > "}},
		{prompt: "RP/0/RSP0/CPU0:xr1#", privileged: true, matches: []string{"RP/0/RSP0/CPU0:xr1#"}},
		{prompt: "core1#", privileged: true, matches: []string{"core1#", "core1(config)#"}},
	}
	for _, tc := range cases {
		t.Run(tc.prompt, func(t *testing.T) {
			p, err := newDevicePrompt(tc.prompt)
			if err != nil {
				t.Fatal(err)
			}
			if p.privileged != tc.privileged {
				t.Fatalf("privileged = %v, want %v", p.privileged, tc.privileged)
			}
			for _, m := range tc.matches {
				if !p.re.MatchString(m) {
					t.Errorf("regex %q does not match %q", p.re, m)
				}
			}
			for _, r := range tc.rejects {
				if p.re.MatchString(r) {
					t.Errorf("regex %q unexpectedly matches %q", p.re, r)
				}
			}
		})
	}

	for _, bad := range []string{"", "no terminator", "just words here", "a line\nwith a newline\n", "-1#"} {
		if _, err := newDevicePrompt(bad); err == nil {
			t.Errorf("newDevicePrompt(%q) accepted a non-prompt line", bad)
		}
	}
}

// TestFakeShellSmoke drives the scripted fake shell with a plain command —
// the smoke test for the test server itself.
func TestFakeShellSmoke(t *testing.T) {
	fake := startFakeShellServer(t, "Welcome\n", "smoke1> ", shellScript{
		"show version": {lines: []string{"Version 1.2.3", "smoke1> "}},
	})
	sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
	prompt := cbLearnPrompt(t, sess)
	if prompt.line != "smoke1>" {
		t.Fatalf("learned prompt = %q, want smoke1>", prompt.line)
	}
	if got := cbCollectOne(t, sess, "show version", prompt); got != "Version 1.2.3\n" {
		t.Fatalf("collect = %q, want %q", got, "Version 1.2.3\n")
	}
}

func TestShellPromptLearning(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		prompt string
		want   string
	}{
		{"cisco style", "sw1 booting\n", "sw1> ", "sw1>"},
		{"linux style", "", "admin@edge:~$ ", "admin@edge:~$"},
		{"mikrotik style", "MikroTik RouterOS 7.15 (c) 2026\n", "[admin@MikroTik] > ", "[admin@MikroTik] >"},
		{"iosxr style", "", "RP/0/RSP0/CPU0:xr1# ", "RP/0/RSP0/CPU0:xr1#"},
		{
			name:   "banner ending in a colon is rejected",
			banner: "Welcome to sw1:\nAuthorized access only:\n",
			prompt: "sw1> ",
			want:   "sw1>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := startFakeShellServer(t, tc.banner, tc.prompt, shellScript{})
			sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
			prompt := cbLearnPrompt(t, sess)
			if prompt.line != tc.want {
				t.Fatalf("learned prompt = %q, want %q", prompt.line, tc.want)
			}
		})
	}

	t.Run("rejected learning fails", func(t *testing.T) {
		// A device that echoes a different line after each newline never
		// yields a stable prompt: learning must fail, not guess.
		fake := startFakeShellServer(t, "", "? ", shellScript{
			"": {lines: []string{"? "}},
		})
		sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.learnPrompt(ctx); err == nil {
			t.Fatal("learning accepted an unstable prompt")
		}
	})
}

func TestShellCollect(t *testing.T) {
	pagerScript := func(marker string, continuation ...string) shellScript {
		// The pager continuation starts on a fresh line, the way a device
		// terminates the marker line when the answer dismisses it.
		lines := append([]string{""}, continuation...)
		lines = append(lines, "sw1> ")
		return shellScript{
			"show running-config": {lines: []string{"hostname sw1", marker}},
			" ":                   {lines: lines},
			"q":                   {lines: []string{"", "sw1> "}},
		}
	}
	cases := []struct {
		name    string
		script  shellScript
		pagers  []pagerPattern
		want    string
		notWant []string
	}{
		{
			name:    "collection to prompt strips echo and prompt",
			script:  shellScript{"show running-config": {lines: []string{"hostname sw1", "snmp-server community public", "sw1> "}}},
			want:    "hostname sw1\nsnmp-server community public\n",
			notWant: []string{"show run", "sw1>"},
		},
		{
			name:    "ansi colors stripped",
			script:  shellScript{"show running-config": {lines: []string{"\x1b[32mhostname\x1b[0m sw1", "sw1> "}}},
			want:    "hostname sw1\n",
			notWant: []string{"\x1b"},
		},
		{
			name:    "carriage return redraws erased",
			script:  shellScript{"show running-config": {lines: []string{"building config...\r             \rdone", "sw1> "}}},
			want:    "done\n",
			notWant: []string{"building config..."},
		},
		{
			name:    "wrapped echo removed",
			script:  shellScript{"show running-config": {echo: "show runn\ning-config", lines: []string{"hostname sw1", "sw1> "}}},
			want:    "hostname sw1\n",
			notWant: []string{"show runn", "ing-config"},
		},
		{
			name:    "--More-- pager answered with space",
			script:  pagerScript("--More--", "interface GigabitEthernet0/1"),
			want:    "hostname sw1\ninterface GigabitEthernet0/1\n",
			notWant: []string{"--More--"},
		},
		{
			name:    "-- More -- pager answered with space",
			script:  pagerScript("-- More --", "interface GigabitEthernet0/1"),
			want:    "hostname sw1\ninterface GigabitEthernet0/1\n",
			notWant: []string{"-- More --"},
		},
		{
			name:    "Press any key pager answered with space",
			script:  pagerScript("Press any key to continue", "interface GigabitEthernet0/1"),
			want:    "hostname sw1\ninterface GigabitEthernet0/1\n",
			notWant: []string{"Press any key"},
		},
		{
			name:    "(END) pager answered with q",
			script:  pagerScript("(END)", "should not be sent"),
			want:    "hostname sw1\n",
			notWant: []string{"(END)", "should not be sent"},
		},
		{
			name:    "plan supplied pager pattern answered",
			script:  pagerScript("::CUSTOM-PAGER::", "interface GigabitEthernet0/1"),
			pagers:  append(builtinPagerPatterns(), pagerPattern{re: mustCompile(`::CUSTOM-PAGER::(?:\r?\n)?`), answer: " "}),
			want:    "hostname sw1\ninterface GigabitEthernet0/1\n",
			notWant: []string{"::CUSTOM-PAGER::"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := startFakeShellServer(t, "", "sw1> ", tc.script)
			pagers := tc.pagers
			if pagers == nil {
				pagers = builtinPagerPatterns()
			}
			sess := cbShellSession(t, fake.addr, pagers)
			prompt := cbLearnPrompt(t, sess)
			got := cbCollectOne(t, sess, "show running-config", prompt)
			if got != tc.want {
				t.Fatalf("collect = %q, want %q", got, tc.want)
			}
			for _, n := range tc.notWant {
				if strings.Contains(got, n) {
					t.Errorf("collect contains %q: %q", n, got)
				}
			}
		})
	}

	t.Run("pager answer positions", func(t *testing.T) {
		// Every --More-- position gets exactly one space; the less-style
		// (END) marker is answered with q instead.
		fake := startFakeShellServer(t, "", "sw1> ", pagerScript("(END)"))
		sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
		prompt := cbLearnPrompt(t, sess)
		got := cbCollectOne(t, sess, "show running-config", prompt)
		if got != "hostname sw1\n" {
			t.Fatalf("collect = %q", got)
		}
		answered := fake.receivedLines()
		var qCount, spaceCount int
		for _, line := range answered {
			switch line {
			case "q":
				qCount++
			case " ":
				spaceCount++
			}
		}
		if qCount != 1 || spaceCount != 0 {
			t.Fatalf("(END) answered with q=%d space=%d, want q=1 space=0", qCount, spaceCount)
		}
	})

	t.Run("step timeout", func(t *testing.T) {
		// The command never returns a prompt: collection ends at the deadline.
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"show running-config": {lines: []string{"hostname sw1"}},
		})
		sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
		prompt := cbLearnPrompt(t, sess)
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		if _, err := sess.collect(ctx, "show running-config", prompt); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("collect error = %v, want context.DeadlineExceeded", err)
		}
	})
}

func TestShellPrivilegedStep(t *testing.T) {
	enableScript := func(afterSecret shellReply) shellScript {
		return shellScript{
			"enable":    {lines: []string{"Password: "}},
			"s3cret":    afterSecret,
			"show run":  {lines: []string{"hostname sw1", "sw1# "}},
			"configure": {lines: []string{"Enter configuration commands, one per line.", "sw1(config)# "}},
		}
	}
	cases := []struct {
		name           string
		command        string
		script         shellScript
		prompt         string
		enablePassword string
		wantErr        error
		wantPrivileged bool
	}{
		{
			name:           "password answered",
			command:        "enable",
			script:         enableScript(shellReply{lines: []string{"sw1# "}}),
			prompt:         "sw1> ",
			enablePassword: "s3cret",
			wantPrivileged: true,
		},
		{
			name:           "wrong enable password",
			command:        "enable",
			script:         enableScript(shellReply{lines: []string{"% Access denied", "sw1> "}}),
			prompt:         "sw1> ",
			enablePassword: "s3cret",
			wantErr:        errEnableFailed("x"),
		},
		{
			name:           "device re-asks the password",
			command:        "enable",
			script:         enableScript(shellReply{lines: []string{"Password: "}}),
			prompt:         "sw1> ",
			enablePassword: "s3cret",
			wantErr:        errEnableFailed("x"),
		},
		{
			name:           "no enable password supplied",
			command:        "enable",
			script:         enableScript(shellReply{lines: []string{"sw1# "}}),
			prompt:         "sw1> ",
			enablePassword: "",
			wantErr:        errEnableFailed("x"),
		},
		{
			name:           "mode changing step re-learns the prompt",
			command:        "configure",
			script:         enableScript(shellReply{lines: []string{"sw1(config)# "}}),
			prompt:         "sw1> ",
			enablePassword: "s3cret",
			wantPrivileged: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := startFakeShellServer(t, "", tc.prompt+" ", tc.script)
			sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
			prompt := cbLearnPrompt(t, sess)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			step := &pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED, Command: tc.command}
			next, err := sess.runPrivileged(ctx, step, tc.enablePassword, prompt)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("privileged step succeeded, want ENABLE_FAILED")
				}
				if !isEnableFailed(err) {
					t.Fatalf("error = %v (%T), want an enable-failed error", err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if next.privileged != tc.wantPrivileged {
				t.Fatalf("prompt %q privileged = %v, want %v", next.line, next.privileged, tc.wantPrivileged)
			}
		})
	}

	t.Run("already privileged skips the step", func(t *testing.T) {
		fake := startFakeShellServer(t, "", "core1# ", shellScript{
			"enable":   {lines: []string{"UNREACHABLE"}},
			"show run": {lines: []string{"hostname core1", "core1# "}},
		})
		sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
		prompt := cbLearnPrompt(t, sess)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		step := &pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED, Command: "enable"}
		next, err := sess.runPrivileged(ctx, step, "s3cret", prompt)
		if err != nil {
			t.Fatal(err)
		}
		if !next.privileged {
			t.Fatalf("prompt %q should be privileged", next.line)
		}
		for _, line := range fake.receivedLines() {
			if line == "enable" || line == "s3cret" {
				t.Fatalf("privileged step sent %q to an already-privileged device", line)
			}
		}
	})

	t.Run("command after a mode change uses the new prompt", func(t *testing.T) {
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"enable":   {lines: []string{"sw1# "}},
			"s3cret":   {lines: []string{"sw1# "}},
			"show run": {lines: []string{"hostname sw1", "sw1# "}},
		})
		sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
		prompt := cbLearnPrompt(t, sess)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		step := &pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED, Command: "enable"}
		prompt, err := sess.runPrivileged(ctx, step, "s3cret", prompt)
		if err != nil {
			t.Fatal(err)
		}
		if got := cbCollectOne(t, sess, "show run", prompt); got != "hostname sw1\n" {
			t.Fatalf("collect after enable = %q", got)
		}
	})
}

func TestShellSessionCleanup(t *testing.T) {
	fake := startFakeShellServer(t, "", "sw1> ", shellScript{
		"show run": {lines: []string{"hostname sw1", "sw1> "}},
	})
	before := runtime.NumGoroutine()
	client, err := ssh.Dial("tcp", fake.addr, &ssh.ClientConfig{
		User:            "backup",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := newShellSession(client, defaultMaxConfigBytes, builtinPagerPatterns())
	if err != nil {
		t.Fatal(err)
	}
	prompt := cbLearnPrompt(t, sess)
	if got := cbCollectOne(t, sess, "show run", prompt); got == "" {
		t.Fatal("empty collect")
	}
	sess.close()
	_ = client.Close() // the connection's goroutines count too
	// The reader, copiers and connection goroutines must all be gone.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: before %d, after %d", before, runtime.NumGoroutine())
}

func TestShellTooLarge(t *testing.T) {
	// A device pushing past the job's byte cap ends the collection with
	// errConfigBackupTooLarge instead of growing the buffer without end.
	fake := startFakeShellServer(t, "", "sw1> ", shellScript{
		"show flood": {lines: []string{strings.Repeat("a", 4096) + "\nsw1> "}},
	})
	client, err := ssh.Dial("tcp", fake.addr, &ssh.ClientConfig{
		User:            "backup",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	sess, err := newShellSession(client, 1024, builtinPagerPatterns())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.close()
	prompt := cbLearnPrompt(t, sess)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sess.collect(ctx, "show flood", prompt); !errors.Is(err, errConfigBackupTooLarge) {
		t.Fatalf("collect error = %v, want errConfigBackupTooLarge", err)
	}
	if len(sess.filter.Bytes()) > 1024 {
		t.Fatalf("filter retained %d bytes, want at most 1024", len(sess.filter.Bytes()))
	}
}

// cbFailWriter is a stdin pipe stub: the failOn-th Write returns err. It
// covers send() failure branches without a real device.
type cbFailWriter struct {
	calls  int
	failOn int
	err    error
}

func (w *cbFailWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failOn {
		return 0, w.err
	}
	return len(p), nil
}

func (w *cbFailWriter) Close() error { return nil }

// cbCancelWriter cancels the session context on the cancelOn-th write, so
// the next quietRead observes a dead context deterministically.
type cbCancelWriter struct {
	calls    int
	cancelOn int
	cancel   context.CancelFunc
}

func (w *cbCancelWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.cancelOn {
		w.cancel()
	}
	return len(p), nil
}

func (w *cbCancelWriter) Close() error { return nil }

// cbStubSession builds a shellSession without a device: stdin is the
// supplied writer, eofC stays open and the filter starts empty.
func cbStubSession(stdin io.WriteCloser) *shellSession {
	return &shellSession{
		stdin:  stdin,
		filter: newShellFilter(0),
		eofC:   make(chan struct{}),
		pagers: builtinPagerPatterns(),
	}
}

func TestShellSessionSetupErrors(t *testing.T) {
	t.Run("closed client cannot open a session", func(t *testing.T) {
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{})
		defer fake.cleanup()
		client := cbShellClient(t, fake.addr)
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := newShellSession(client, defaultMaxConfigBytes, nil); err == nil {
			t.Fatal("newShellSession succeeded on a closed client")
		}
	})

	t.Run("device refusing a PTY fails the session", func(t *testing.T) {
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(nil, nil))
		defer cleanup()
		if _, err := newShellSession(cbShellClient(t, addr), defaultMaxConfigBytes, nil); err == nil {
			t.Fatal("newShellSession succeeded without a PTY")
		}
	})

	t.Run("device refusing a shell fails the session", func(t *testing.T) {
		// pty-req is granted but the shell request is refused.
		config := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return nil, nil
			},
		}
		config.AddHostKey(cbNewSigner(t))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }()
					sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
					if err != nil {
						return
					}
					defer func() { _ = sconn.Close() }()
					go ssh.DiscardRequests(reqs)
					for newChannel := range chans {
						if newChannel.ChannelType() != "session" {
							_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
							continue
						}
						_, requests, err := newChannel.Accept()
						if err != nil {
							continue
						}
						go func() {
							for req := range requests {
								_ = req.Reply(req.Type == "pty-req", nil)
							}
						}()
					}
				}()
			}
		}()
		if _, err := newShellSession(cbShellClient(t, ln.Addr().String()), defaultMaxConfigBytes, nil); err == nil {
			t.Fatal("newShellSession succeeded without a shell")
		}
	})
}

func TestShellLearnPromptFailures(t *testing.T) {
	t.Run("deadline before the login banner", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := sess.learnPrompt(ctx); err == nil {
			t.Fatal("learnPrompt succeeded on a dead context")
		}
	})

	t.Run("first newline write fails", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{failOn: 1, err: io.ErrClosedPipe})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.learnPrompt(ctx); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("learnPrompt error = %v, want io.ErrClosedPipe", err)
		}
	})

	t.Run("second newline write fails", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{failOn: 2, err: io.ErrClosedPipe})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.learnPrompt(ctx); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("learnPrompt error = %v, want io.ErrClosedPipe", err)
		}
	})

	t.Run("deadline during the second probe", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sess := cbStubSession(&cbCancelWriter{cancelOn: 2, cancel: cancel})
		if _, err := sess.learnPrompt(ctx); err == nil {
			t.Fatal("learnPrompt succeeded after the deadline")
		}
	})

	t.Run("silent device never shows a prompt", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.learnPrompt(ctx); err == nil {
			t.Fatal("learnPrompt accepted silence as a prompt")
		}
	})
}

func TestShellCollectFailures(t *testing.T) {
	t.Run("command write fails", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{failOn: 1, err: io.ErrClosedPipe})
		prompt, err := newDevicePrompt("sw1>")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.collect(ctx, "show run", prompt); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("collect error = %v, want io.ErrClosedPipe", err)
		}
	})

	t.Run("prompt discovered on a quiet cycle", func(t *testing.T) {
		// Output that arrives without an arrived-signal (a copier racing
		// the wait loop) is still picked up when the quiet timer fires.
		sess := cbStubSession(&cbFailWriter{})
		prompt, err := newDevicePrompt("sw1>")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(20 * time.Millisecond)
			sess.filter.mu.Lock()
			sess.filter.out = append(sess.filter.out, "hostname sw1\nsw1> "...)
			sess.filter.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, err := sess.collect(ctx, "show run", prompt)
		if err != nil {
			t.Fatal(err)
		}
		if got != "hostname sw1\n" {
			t.Fatalf("collect = %q, want %q", got, "hostname sw1\n")
		}
	})
}

func TestShellPrivilegedFailures(t *testing.T) {
	newPrompt := func(t *testing.T, line string) *devicePrompt {
		t.Helper()
		p, err := newDevicePrompt(line)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	step := &pb.ConfigBackupStep{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_PRIVILEGED, Command: "enable"}

	t.Run("enable command write fails", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{failOn: 1, err: io.ErrClosedPipe})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.runPrivileged(ctx, step, "s3cret", newPrompt(t, "sw1>")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("runPrivileged error = %v, want io.ErrClosedPipe", err)
		}
	})

	t.Run("password write fails", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{failOn: 2, err: io.ErrClosedPipe})
		sess.filter.mu.Lock()
		sess.filter.out = append(sess.filter.out, "Password: "...)
		sess.filter.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.runPrivileged(ctx, step, "s3cret", newPrompt(t, "sw1>")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("runPrivileged error = %v, want io.ErrClosedPipe", err)
		}
	})

	t.Run("prompt shape the parser rejects", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{})
		sess.filter.mu.Lock()
		sess.filter.out = append(sess.filter.out, "-1# "...)
		sess.filter.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.runPrivileged(ctx, step, "s3cret", newPrompt(t, "sw1>")); err == nil {
			t.Fatal("runPrivileged accepted an unparseable prompt")
		}
	})

	t.Run("session ends during enable", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{})
		close(sess.eofC)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := sess.runPrivileged(ctx, step, "s3cret", newPrompt(t, "sw1>")); !errors.Is(err, errShellClosed) {
			t.Fatalf("runPrivileged error = %v, want errShellClosed", err)
		}
	})

	t.Run("deadline during enable", func(t *testing.T) {
		sess := cbStubSession(&cbFailWriter{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := sess.runPrivileged(ctx, step, "s3cret", newPrompt(t, "sw1>")); !errors.Is(err, context.Canceled) {
			t.Fatalf("runPrivileged error = %v, want context.Canceled", err)
		}
	})
}

func TestShellCloseStuckWrite(t *testing.T) {
	// A device that never drains stdin leaves the exit write stuck: close
	// abandons it after shellWriteDeadline instead of waiting forever.
	fake := startFakeShellServer(t, "", "sw1> ", shellScript{})
	defer fake.cleanup()
	sess := cbShellSession(t, fake.addr, builtinPagerPatterns())
	sess.stdin = &cbFailWriter{failOn: -1, err: io.ErrClosedPipe}
	done := make(chan struct{})
	go func() {
		sess.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close hung on a stuck exit write")
	}
}

func TestMustCompilePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustCompile accepted an invalid regex")
		}
	}()
	mustCompile("[unterminated")
}

func TestShellTextHelpers(t *testing.T) {
	prompt, err := newDevicePrompt("sw1>")
	if err != nil {
		t.Fatal(err)
	}

	if got := stripEchoedCommand("output\n", "  \t "); got != "output\n" {
		t.Fatalf("stripEchoedCommand with a blank command = %q", got)
	}
	deep := "1\n2\n3\n4\n5\n6\n7\n8\n9\necho of a\nsw1> "
	if got := stripEchoedCommand(deep, "echo of a"); got != deep {
		t.Fatal("stripEchoedCommand scanned past its line limit")
	}
	if got := stripTrailingPrompt("\n\n", prompt); got != "\n\n" {
		t.Fatalf("stripTrailingPrompt on empty text = %q", got)
	}
	if got := stripTrailingPrompt("body\nrouter2> ", prompt); got != "body\nrouter2> " {
		t.Fatal("stripTrailingPrompt removed a non-prompt line")
	}
	if got := lastLine("no newline here"); got != "no newline here" {
		t.Fatalf("lastLine without a newline = %q", got)
	}
}

func TestSincePastEnd(t *testing.T) {
	sess := &shellSession{filter: newShellFilter(0)}
	sess.filter.mu.Lock()
	sess.filter.out = []byte("ab")
	sess.filter.mu.Unlock()
	if got := sess.since(5); got != "" {
		t.Fatalf("since past the buffer end = %q, want \"\"", got)
	}
}
