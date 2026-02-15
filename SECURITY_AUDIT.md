# TowerOps Agent — Security Audit

**Date:** 2026-02-15
**Auditor:** Automated security review
**Codebase:** Go agent, 22 files, ~2,200 LOC
**Dependencies:** gosnmp v1.43.2, golang.org/x/crypto v0.48.0, golang.org/x/net v0.50.0, protobuf v1.36.11

---

## Executive Summary

The agent is reasonably well-written with several good security practices already in place (HTTPS-only updates, SHA-256 checksum verification, constant-time comparison, TLS 1.2 minimum, sanitized URL logging, frame size limits). The main issues center around credential handling in memory, TLS verification bypass for device connections, and a TOCTOU race in the self-update mechanism.

**Critical:** 0 | **High:** 3 | **Medium:** 6 | **Low:** 5

---

## Findings

### HIGH-1: SSH Host Key Verification Disabled
- **File:** `ssh.go`, line 22
- **Severity:** HIGH
- **Code:** `HostKeyCallback: ssh.InsecureIgnoreHostKey()`
- **Issue:** MITM attacks can intercept SSH connections to MikroTik devices, capturing credentials (username/password sent in the clear during SSH auth). An attacker on the network path can impersonate any device.
- **Context:** The comment acknowledges this is intentional for dynamic device provisioning. This is a common trade-off for network management agents but remains a real risk.
- **Fix:** Implement a trust-on-first-use (TOFU) model: store host keys on first connection, reject mismatches on subsequent connections. Alternatively, allow the server to push known host keys per device. At minimum, log a warning when connecting to a new/changed host key.

### HIGH-2: MikroTik API TLS Verification Disabled
- **File:** `mikrotik.go`, line 29
- **Severity:** HIGH
- **Code:** `InsecureSkipVerify: true`
- **Issue:** Same MITM risk as SSH — MikroTik API credentials (username/password) are sent over a TLS connection that doesn't verify the server's identity. An attacker can present any certificate and capture credentials.
- **Fix:** Same TOFU approach as SSH. Pin certificate fingerprints per device, or at minimum verify the certificate's Subject/SAN matches the expected device IP.

### HIGH-3: Self-Update TOCTOU Race Condition
- **File:** `update.go`, lines 55-72
- **Severity:** HIGH
- **Code:** `osWriteFile(tempPath, body, 0700)` → `osRename(tempPath, currentExe)`
- **Issue:** Between writing the temp file (with verified checksum) and renaming it, another process could replace the temp file with a malicious binary. The rename then places the attacker's binary as the agent executable, which is immediately executed via `syscall.Exec`.
- **Fix:** Write to a temp file in a directory only writable by the agent's user. Use `O_EXCL` to ensure the file is newly created. Better yet, use `os.CreateTemp` in the same directory, write+verify, then `os.Rename` atomically. Since rename on the same filesystem is atomic on Linux, the real fix is to **re-verify the checksum after writing** or use `O_EXCL` + restrictive directory permissions. Also consider using `renameat2` with `RENAME_NOREPLACE` to detect races.

### MEDIUM-1: Credentials Stored as Go Strings (Cannot Be Zeroed)
- **File:** `snmp.go` (passphrase fields), `ssh.go` (password param), `mikrotik.go` (password param)
- **Severity:** MEDIUM
- **Issue:** SNMP community strings, SNMPv3 auth/priv passwords, SSH passwords, and MikroTik passwords are all Go `string` types (from protobuf). Go strings are immutable and their backing memory cannot be zeroed. Credentials persist in memory until GC collects them and the OS reclaims the pages.
- **Context:** The codebase has a `zeroBytes()` utility and the comment in `agent.go` acknowledges this limitation. The protobuf-generated code forces string types.
- **Fix:** This is a Go+protobuf limitation. Mitigation: minimize credential lifetime by not retaining protobuf job objects longer than needed (already done — jobs are processed and discarded). For defense-in-depth, consider using `[]byte` wrappers where possible and zeroing after use, though this requires custom protobuf handling. Low practical exploitability unless the host is already compromised (at which point attacker can just read the token anyway).

### MEDIUM-2: Token Passed via Command-Line Argument
- **File:** `main.go`, line 23
- **Severity:** MEDIUM
- **Code:** `flag.String("token", os.Getenv("TOWEROPS_AGENT_TOKEN"), ...)`
- **Issue:** When `--token` is used (vs env var), the token is visible in `/proc/<pid>/cmdline` to all users on the system. The `sanitizeArgs` function in `update.go` masks it in logs but not in the process table.
- **Fix:** Prefer env var only. If CLI flag must be supported, read token from a file (`--token-file`) or stdin. Document that env var is the recommended approach.

### MEDIUM-3: Plaintext WebSocket (ws://) Supported
- **File:** `websocket.go`, lines 58-66; `main.go` `toWebSocketURL()`
- **Severity:** MEDIUM
- **Issue:** The agent supports `ws://` (unencrypted) connections. If configured with `http://` API URL, all traffic including the auth token and SNMP/SSH credentials flows in plaintext.
- **Fix:** Reject non-TLS connections entirely, or at minimum log a prominent warning. In `WSDial`, refuse to connect if scheme is `ws` unless an explicit `--insecure` flag is set.

### MEDIUM-4: No Read Timeout on WebSocket Connection
- **File:** `websocket.go`, `ReadMessage()` / `readFrame()`
- **Severity:** MEDIUM
- **Issue:** After the handshake, `conn.SetDeadline` is cleared (line 109). The `ReadMessage` loop blocks indefinitely on `io.ReadFull`. If the server stops sending data (without closing the TCP connection), the reader goroutine hangs forever. The channel heartbeat (25s) only detects write failures, not read stalls.
- **Fix:** Set a read deadline before each `readFrame` call (e.g., 90 seconds — 3× the heartbeat interval). Reset it on each successful read. This ensures dead connections are detected.

### MEDIUM-5: Unbounded Channel Buffers Enable Memory Exhaustion
- **File:** `agent.go`, lines 95-99
- **Severity:** MEDIUM
- **Code:** `writeCh: 10000`, `snmpResultCh: 10000`, `mikrotikResultCh: 5000`, etc.
- **Issue:** A malicious or misbehaving server can flood the agent with jobs, filling these channels and consuming significant memory (each result can be substantial). The `writeCh` at 10,000 messages × potential KB each = tens of MB.
- **Fix:** The worker pools provide backpressure (bounded goroutines), but the result channels don't. Consider: (1) smaller channel buffers with drop-on-full (already done for writeCh), (2) monitoring total queued bytes, (3) rate-limiting inbound job acceptance.

### MEDIUM-6: Regex DoS in HTTP Check
- **File:** `checks.go`, line ~107
- **Severity:** MEDIUM
- **Code:** `regexp.MatchString(config.Regex, string(body[:n]))`
- **Issue:** The regex comes from the server (protobuf message). A malicious or compromised server can send a catastrophic backtracking regex (e.g., `(a+)+$`) with a crafted response body, causing CPU exhaustion. Go's `regexp` uses RE2 which is immune to catastrophic backtracking, **so this is actually safe**. However, compiling the regex on every check is wasteful.
- **Fix:** No security fix needed (Go's regexp is safe by design). Consider pre-compiling for performance.

### LOW-1: WebSocket Handshake Response Parsing is Fragile
- **File:** `websocket.go`, lines 93-100
- **Severity:** LOW
- **Issue:** The handshake reads only one `conn.Read()` call (up to 4096 bytes). If the server sends the HTTP response in multiple TCP segments, the agent may fail to parse the full response headers, including `Sec-WebSocket-Accept`. This is unlikely with well-behaved servers but violates robustness.
- **Fix:** Use `bufio.Reader` for the handshake response as well, reading line-by-line until the empty `\r\n\r\n` delimiter.

### LOW-2: No Certificate Pinning for Server Connection
- **File:** `websocket.go`, line 49
- **Severity:** LOW
- **Code:** `tls.Config{MinVersion: tls.VersionTLS12}`
- **Issue:** The agent trusts the system CA store. A compromised CA can issue a fraudulent cert for the TowerOps server. This is standard for most applications but noted for completeness.
- **Fix:** For high-security deployments, support certificate pinning (pin the server's public key or a specific CA). This is defense-in-depth, not a practical vulnerability for most environments.

### LOW-3: Update Binary Permissions Too Broad
- **File:** `update.go`, line 60
- **Severity:** LOW
- **Code:** `osWriteFile(tempPath, body, 0700)`
- **Issue:** `0700` is correct for owner-only execution, but the temp file is created in the same directory as the binary. If that directory has world-write permissions (unlikely but possible), other users could interfere.
- **Fix:** Verify the parent directory permissions before writing, or use a dedicated temp directory owned by the agent user.

### LOW-4: Error Messages May Leak Internal State
- **File:** `mikrotik.go`, `snmp.go`, `ssh.go` (various error paths)
- **Severity:** LOW
- **Issue:** Error messages like `"ssh dial 10.0.0.1:22: connection refused"` are sent back to the server as result payloads. While the server should already know the device IPs, detailed error messages could leak internal network topology info if the server is compromised.
- **Fix:** Consider categorizing errors (connection_failed, auth_failed, timeout) rather than forwarding raw error strings.

### LOW-5: Worker Pool Panic Recovery Swallows Stack Traces
- **File:** `workerpool.go`, line 22
- **Severity:** LOW
- **Code:** `slog.Error("worker panic recovered", "error", r)`
- **Issue:** Only the panic value is logged, not the stack trace. This makes debugging difficult and could mask security-relevant crashes.
- **Fix:** Use `debug.Stack()` to capture and log the full stack trace on panic.

---

## Positive Security Observations

These are things done well:

1. **HTTPS-only updates** (`update.go:22`) — rejects non-HTTPS download URLs
2. **SHA-256 checksum with constant-time compare** (`update.go:42`) — prevents timing attacks and ensures binary integrity
3. **TLS 1.2 minimum** on all TLS connections (`websocket.go:49`, `mikrotik.go:29`)
4. **`crypto/rand`** used for WebSocket key generation (not `math/rand`)
5. **URL sanitization in logs** (`main.go:sanitizeURL`) — query params masked
6. **Token masking** in `sanitizeArgs` for update re-exec
7. **Frame size limits** — `maxFrameSize` (16MB), `maxMikrotikWordSize` (10MB), `maxUpdateSize` (100MB), `maxJobPayloadBytes` (4MB)
8. **Connection timeouts** on SNMP (10s), SSH (30s), MikroTik (30s), ping (5s)
9. **Worker pools** with bounded concurrency prevent goroutine exhaustion
10. **Context propagation** throughout for clean shutdown
11. **Backoff with jitter** on reconnect prevents thundering herd
12. **`zeroBytes` utility** exists and is used for protobuf serialization buffers

## Dependency Assessment

All dependencies are at current/recent versions as of audit date:
- `golang.org/x/crypto v0.48.0` — no known CVEs
- `golang.org/x/net v0.50.0` — no known CVEs
- `gosnmp v1.43.2` — no known CVEs
- `google.golang.org/protobuf v1.36.11` — no known CVEs

**Recommendation:** Run `govulncheck` periodically in CI to catch newly disclosed vulnerabilities.

---

## Recommendations Summary (Priority Order)

1. **Implement TOFU host key verification** for SSH and MikroTik TLS (HIGH-1, HIGH-2)
2. **Fix TOCTOU in self-update** with exclusive file creation and directory permission checks (HIGH-3)
3. **Add WebSocket read timeouts** to detect dead connections (MEDIUM-4)
4. **Reject plaintext WebSocket connections** or require explicit opt-in (MEDIUM-3)
5. **Prefer env var / token-file** over CLI flag for token (MEDIUM-2)
6. **Add `govulncheck`** to CI pipeline
7. **Log stack traces** on worker panics (LOW-5)
