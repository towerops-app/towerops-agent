package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/towerops-app/towerops-agent/pb"
	"golang.org/x/crypto/ssh"
)

// stepFailedError exists so shellStep's error return can distinguish a
// device-side COMMAND_UNSUPPORTED from a transport failure; its Error() and
// the isStepFailure assertion are dead in coverage terms unless a test calls
// them directly.
func TestStepFailedError(t *testing.T) {
	failure := &planStepFailure{code: pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED, detail: "bad command"}
	err := error(stepFailedError{failure: failure})

	if err.Error() != "bad command" {
		t.Fatalf("Error() = %q, want the failure detail", err.Error())
	}
	if !isStepFailure(err) {
		t.Fatal("isStepFailure(stepFailedError) = false")
	}
	if isStepFailure(errors.New("transport down")) {
		t.Fatal("isStepFailure(plain error) = true")
	}
}

// TestClassifyStepOutput covers the scanner edges the device tests don't
// reach: blank lines are skipped, only the first stepFailureScanLines count,
// and stderr is scanned when stdout is clean.
func TestClassifyStepOutput(t *testing.T) {
	if f := classifyStepOutput("\n\nok\n\n", ""); f != nil {
		t.Fatalf("blank lines classified as a failure: %+v", f)
	}
	if f := classifyStepOutput(strings.Repeat("noise line\n", stepFailureScanLines)+"% Invalid input\n", ""); f != nil {
		t.Fatalf("failure text past the scan window was caught: %+v", f)
	}
	if f := classifyStepOutput("clean output\n", "% Invalid input\n"); f == nil ||
		f.code != pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED {
		t.Fatalf("stderr failure missed or misclassified: %+v", f)
	}
}

// TestPlanRunnerInternals covers the runner paths no device scenario
// reaches: include() after a failure, the pager-pattern compile fallback,
// successResult's failed and gzip-error branches, and privilegedFailure's
// non-enable error mapping.
func TestPlanRunnerInternals(t *testing.T) {
	cb := &pb.ConfigBackupJob{Plan: &pb.ConfigBackupPlan{
		PagerPatterns: []string{"[unterminated", `::MARKER::(?:\r?\n)?`},
	}}
	r := newPlanRunner(context.Background(), nil, cb, "job-1", "dev-1")
	if len(r.pagers) != len(builtinPagerPatterns())+1 {
		t.Fatalf("pagers = %d, want builtins plus the one valid custom pattern", len(r.pagers))
	}

	r.failed = true
	r.include("sec", "must not land\n")
	if len(r.shared.Bytes()) != 0 {
		t.Fatalf("include wrote %d bytes after failure", len(r.shared.Bytes()))
	}
	result := r.successResult()
	if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
		t.Fatalf("successResult on a failed runner = %v, want TOO_LARGE", result.ErrorCode)
	}

	orig := gzipTo
	defer func() { gzipTo = orig }()
	gzipTo = func(io.Writer, []byte) error { return errors.New("gzip boom") }
	r.failed = false
	result = r.successResult()
	if result.ErrorCode != pb.ConfigBackupErrorCode_INTERNAL {
		t.Fatalf("successResult on gzip failure = %v, want INTERNAL", result.ErrorCode)
	}

	if got := r.privilegedFailure(context.Background(), errShellClosed); got.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_FAILED {
		t.Fatalf("privilegedFailure(errShellClosed) = %v, want EXPORT_FAILED", got.ErrorCode)
	}
	if got := r.privilegedFailure(context.Background(), context.DeadlineExceeded); got.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
		t.Fatalf("privilegedFailure(deadline) = %v, want TIMEOUT", got.ErrorCode)
	}
}

// TestRedactKeyFragments covers the 4 KiB scan cap that device output never
// reaches: key material past it is left as-is.
func TestRedactKeyFragments(t *testing.T) {
	fragment := strings.Repeat("k", keyFragmentLen)
	body := fragment + strings.Repeat("z", 64)

	got := redactKeyFragments("before "+fragment+" after", body)
	if !strings.Contains(got, "***") || strings.Contains(got, fragment) {
		t.Fatalf("fragment not redacted: %q", got)
	}

	// Only the first 4 KiB of the detail is scanned at all.
	long := strings.Repeat("x", 4096) + fragment
	if got = redactKeyFragments(long, body); got != strings.Repeat("x", 4096) {
		t.Fatalf("scan window not respected: got %d bytes ending %q", len(got), got[len(got)-32:])
	}
}

// TestPlanExecFailures drives the exec-transport failure paths the step
// table can't express: a stall that hits the per-step deadline, output past
// the byte cap, non-zero exits whose stdout is the detail, and the
// exec-only skip of privileged steps.
func TestPlanExecFailures(t *testing.T) {
	t.Run("step deadline reports TIMEOUT", func(t *testing.T) {
		resetHostKeyStore(t)
		// The device accepts the command then goes silent; the step's own
		// deadline must bound it.
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), func(ch ssh.Channel, command string) {
			_, _ = ch.Write([]byte("collecting"))
			time.Sleep(2 * time.Second) // stall until the step deadline kills the session
			_ = ch.Close()
		})
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		plan := cbExecPlan(cbCommand("show stall"))
		plan.StepTimeoutMs = 400
		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
			t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("oversized step output is TOO_LARGE", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show flood": {out: strings.Repeat("x", 4096)},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		job := cbPlanJob(host, port, cbExecPlan(cbCommand("show flood")))
		job.ConfigBackup.MaxConfigBytes = 256
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
			t.Fatalf("code = %v (%q), want TOO_LARGE", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("non-zero exit uses stdout as the detail", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show opaque": {out: "half of a reply\n", exit: 2},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbExecPlan(cbCommand("show opaque"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED {
			t.Fatalf("code = %v (%q), want COMMAND_UNSUPPORTED", result.ErrorCode, result.ErrorDetail)
		}
		if result.ErrorDetail != "half of a reply" {
			t.Fatalf("detail = %q, want the step's stdout", result.ErrorDetail)
		}
	})

	t.Run("non-zero exit without output uses the transport error", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show silent": {exit: 1},
		}, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbExecPlan(cbCommand("show silent"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_COMMAND_UNSUPPORTED {
			t.Fatalf("code = %v (%q), want COMMAND_UNSUPPORTED", result.ErrorCode, result.ErrorDetail)
		}
		if result.ErrorDetail == "" {
			t.Fatal("empty detail for a failed command")
		}
	})

	t.Run("privileged steps are skipped on exec", func(t *testing.T) {
		resetHostKeyStore(t)
		var mu sync.Mutex
		var seen []string
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(map[string]cbExecResponse{
			"show running-config": {out: "hostname sw1\n"},
		}, func(cmd string) {
			mu.Lock()
			seen = append(seen, cmd)
			mu.Unlock()
		}))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbExecPlan(cbPrivileged("enable"), cbCommand("show running-config"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range seen {
			if cmd == "enable" {
				t.Fatal("exec transport sent a privileged-mode command")
			}
		}
	})
}

// TestPlanShellFailures drives the shell-transport failure paths: session
// setup errors, privileged-mode failures mid-plan and after the prompt, the
// enable deadline, and output that crosses the cap between steps.
func TestPlanShellFailures(t *testing.T) {
	t.Run("device without a PTY fails session setup", func(t *testing.T) {
		resetHostKeyStore(t)
		addr, cleanup := startTestSSHServerWithSigner(t, cbNewSigner(t), cbExecHandler(nil, nil))
		defer cleanup()
		host, port := cbAddrPort(t, addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbShellPlan(cbCommand("show run"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatal("shell plan succeeded against an exec-only device")
		}
	})

	t.Run("unlearnable prompt fails the plan", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "? ", shellScript{
			"": {lines: []string{"? "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, cbShellPlan(cbCommand("show run"))), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_EXPORT_FAILED {
			t.Fatalf("code = %v (%q), want EXPORT_FAILED", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("privileged step enters enable mode", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"enable":   {lines: []string{"Password: "}},
			"s3cret":   {lines: []string{"sw1# "}},
			"show run": {lines: []string{"hostname sw1", "sw1# "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbPrivileged("enable"), cbCommand("show run")))
		job.ConfigBackup.EnablePassword = "s3cret"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatalf("code = %v (%q), want OK", result.ErrorCode, result.ErrorDetail)
		}
		if got := cbGunzip(t, result.ConfigGzip); got != "hostname sw1\n" {
			t.Fatalf("config = %q", got)
		}
	})

	t.Run("wrong enable password is ENABLE_FAILED", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"enable":   {lines: []string{"Password: "}},
			"s3cret":   {lines: []string{"% Access denied", "sw1> "}},
			"show run": {lines: []string{"hostname sw1", "sw1# "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbPrivileged("enable"), cbCommand("show run")))
		job.ConfigBackup.EnablePassword = "s3cret"
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_ENABLE_FAILED {
			t.Fatalf("code = %v (%q), want ENABLE_FAILED", result.ErrorCode, result.ErrorDetail)
		}
		for _, line := range fake.receivedLines() {
			if line == "show run" {
				t.Fatal("the plan ran a step after ENABLE_FAILED")
			}
		}
	})

	t.Run("enable step deadline is TIMEOUT", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"enable": {lines: []string{"thinking"}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		plan := cbShellPlan(cbPrivileged("enable"), cbCommand("show run"))
		plan.StepTimeoutMs = 400
		out := testQueue()
		executeConfigBackupJob(context.Background(), cbPlanJob(host, port, plan), out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
			t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("section headers crossing the cap is TOO_LARGE", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{
			"s1": {lines: []string{"o1", "sw1> "}},
			"s2": {lines: []string{"o2", "sw1> "}},
			"s3": {lines: []string{"o3", "sw1> "}},
			"s4": {lines: []string{"o4", "sw1> "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		steps := []*pb.ConfigBackupStep{
			{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "s1", Section: "s1"},
			{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "s2", Section: "s2"},
			{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "s3", Section: "s3"},
			{Kind: pb.ConfigBackupStepKind_CONFIG_BACKUP_STEP_COMMAND, Command: "s4", Section: "s4"},
		}
		plan := cbShellPlan(steps...)
		// The raw session stays under 64 bytes; the headers push the
		// assembled config over it.
		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.MaxConfigBytes = 64
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TOO_LARGE {
			t.Fatalf("code = %v (%q), want TOO_LARGE", result.ErrorCode, result.ErrorDetail)
		}
	})
}

// TestPlanProbeFailures covers the PROBE-mode error paths: a dead
// connection, a device that never shows a prompt within the step deadline,
// and prompt learning that cannot settle.
func TestPlanProbeFailures(t *testing.T) {
	t.Run("session open failure", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "sw1> ", shellScript{})
		defer fake.cleanup()
		client := cbShellClient(t, fake.addr)
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}

		job := cbPlanJob("127.0.0.1", 22, cbShellPlan(cbCommand("show run")))
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		r := newPlanRunner(context.Background(), client, job.ConfigBackup, "job-1", "dev-1")
		result := r.probe(context.Background())
		if result.ErrorCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatal("probe succeeded on a closed client")
		}
	})

	t.Run("silent device is a probe timeout", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "", shellScript{})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		plan := cbShellPlan(cbCommand("show run"))
		plan.StepTimeoutMs = 300
		job := cbPlanJob(host, port, plan)
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode != pb.ConfigBackupErrorCode_TIMEOUT {
			t.Fatalf("code = %v (%q), want TIMEOUT", result.ErrorCode, result.ErrorDetail)
		}
	})

	t.Run("unlearnable prompt fails the probe", func(t *testing.T) {
		resetHostKeyStore(t)
		fake := startFakeShellServer(t, "", "? ", shellScript{
			"": {lines: []string{"? "}},
		})
		defer fake.cleanup()
		host, port := cbAddrPort(t, fake.addr)

		job := cbPlanJob(host, port, cbShellPlan(cbCommand("show run")))
		job.ConfigBackup.Mode = pb.ConfigBackupMode_CONFIG_BACKUP_MODE_PROBE
		out := testQueue()
		executeConfigBackupJob(context.Background(), job, out)

		result := cbReceiveConfigBackupResult(t, out)
		if result.ErrorCode == pb.ConfigBackupErrorCode_CONFIG_BACKUP_OK {
			t.Fatal("probe succeeded against a prompt it cannot learn")
		}
	})
}
