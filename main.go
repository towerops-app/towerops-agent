// Copyright (C) 2026 Graham McIntire
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/towerops-app/towerops-agent/pb"
)

var version = "dev"
var buildDate = "unknown"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	// NotifyContext keeps intercepting signals after it cancels the context.
	// Stop it when shutdown begins so a second signal uses the default handler.
	go stopSignalNotifier(ctx, stop)
	os.Exit(runMain(ctx, os.Args[1:]))
}

func stopSignalNotifier(ctx context.Context, stop context.CancelFunc) {
	<-ctx.Done()
	stop()
}

// runMain is the testable entry point. Returns an exit code.
func runMain(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("towerops-agent", flag.ContinueOnError)
	apiURL := fs.String("api-url", os.Getenv("TOWEROPS_API_URL"), "API URL (e.g., wss://towerops.net)")
	token := fs.String("token", os.Getenv("TOWEROPS_AGENT_TOKEN"), "Agent authentication token")
	tokenFile := fs.String("token-file", "", "Path to file containing agent token (preferred over --token)")
	logLevel := fs.String("log-level", envOrDefault("info", "TOWEROPS_LOG_LEVEL", "LOG_LEVEL"), "Log level (debug, info, warn, error)")
	logFormat := fs.String("log-format", envOrDefault("text", "TOWEROPS_LOG_FORMAT", "LOG_FORMAT"), "Log output format (text, json)")
	insecure := fs.Bool("insecure", envBool(false, "TOWEROPS_INSECURE"), "Allow plaintext ws:// connections (insecure)")
	trapEnabled := fs.Bool("trap-enabled", envBool(false, "TOWEROPS_TRAP_ENABLED", "TRAP_ENABLED"), "Listen for SNMP traps")
	trapBind := fs.String("trap-bind", envOrDefault("0.0.0.0", "TOWEROPS_TRAP_BIND"), "Address for the SNMP trap listener")
	trapPort := fs.Uint("trap-port", envUint(162, "TOWEROPS_TRAP_PORT", "TRAP_PORT"), "UDP port for the SNMP trap listener")
	trapCommunity := fs.String("trap-community", envFirst("TOWEROPS_TRAP_COMMUNITY", "TRAP_COMMUNITY"), "Only accept traps carrying this community string (default: any)")
	hostKeysFile := fs.String("host-keys-file", envOrDefault(defaultHostKeysPath, "TOWEROPS_HOST_KEYS_FILE"), "Path to the SSH and TLS trust-on-first-use store")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Read token from file if --token-file is provided
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read token file: %v\n", err)
			return 1
		}
		t := strings.TrimSpace(string(data))
		token = &t
	}

	// Warn if --token was used via CLI (visible in /proc/cmdline)
	if *tokenFile == "" && flagIsSet(fs, "token") {
		fmt.Fprintln(os.Stderr, "WARNING: --token flag exposes the token in the process table. Use TOWEROPS_AGENT_TOKEN env var or --token-file instead.")
	}

	level, validLogLevel := resolveLogLevel(*logLevel)
	slog.SetDefault(slog.New(newLogHandler(os.Stderr, level, *logFormat)))
	if !validLogLevel {
		slog.Warn("ignoring unrecognised log level", "value", *logLevel)
	}

	if *apiURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "error: --api-url and --token are required (or set TOWEROPS_API_URL and TOWEROPS_AGENT_TOKEN)")
		fs.Usage()
		return 1
	}
	if err := initHostKeyStore(*hostKeysFile); err != nil {
		slog.Error("host key store", "error", err)
		return 1
	}

	slog.Info("towerops agent starting", "version", version, "built", buildDate)

	// Convert HTTP(S) to WebSocket URL
	wsURL, err := toWebSocketURL(*apiURL, *insecure)
	if err != nil {
		slog.Error(err.Error())
		return 1
	}
	slog.Info("websocket url", "url", sanitizeURL(wsURL))

	// The trap listener outlives individual sessions: devices send traps
	// whenever they like, including while the agent is reconnecting.
	var traps <-chan *pb.SnmpTrap
	if *trapEnabled {
		if *trapPort == 0 || *trapPort > 65535 {
			fmt.Fprintf(os.Stderr, "error: --trap-port must be 1-65535, got %d\n", *trapPort)
			return 1
		}
		listener, err := startTrapListener(*trapBind, uint16(*trapPort), *trapCommunity)
		if err != nil {
			slog.Error("trap listener", "error", err)
			return 1
		}
		defer listener.Close()
		traps = listener.Traps()
	}

	// Run agent with reconnect loop
	runAgent(ctx, wsURL, *token, traps)

	slog.Info("towerops agent stopped")
	return 0
}

// toWebSocketURL converts an HTTP(S) URL to a WebSocket URL.
// Returns an error for plaintext ws:// unless insecure is set.
func toWebSocketURL(rawURL string, insecure bool) (string, error) {
	scheme, remainder, found := strings.Cut(rawURL, "://")

	var result string
	if !found {
		result = "wss://" + rawURL
	} else {
		switch strings.ToLower(scheme) {
		case "http", "ws":
			result = "ws://" + remainder
		case "https", "wss":
			result = "wss://" + remainder
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", scheme)
		}
	}

	if strings.HasPrefix(result, "ws://") && !insecure {
		return "", fmt.Errorf("plaintext ws:// connection rejected — use wss:// or pass --insecure to allow")
	}
	return result, nil
}

// flagIsSet returns true if a flag was explicitly set on the command line.
func flagIsSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// sanitizeURL masks query parameters and userinfo to prevent credential leakage in logs.
func sanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid URL]"
	}
	if u.RawQuery != "" {
		u.RawQuery = "***"
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	return u.String()
}

// resolveLogLevel maps a level name to its slog level, reporting whether the
// name was recognised so the caller can warn instead of silently using info.
func resolveLogLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(value) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// envFirst returns the first non-empty environment value in priority order.
func envFirst(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func envOrDefault(fallback string, keys ...string) string {
	if value := envFirst(keys...); value != "" {
		return value
	}
	return fallback
}

// envBool reads the first set boolean environment variable, ignoring
// unparseable values.
func envBool(fallback bool, keys ...string) bool {
	value := envFirst(keys...)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		slog.Warn("ignoring unparseable environment variable", "keys", strings.Join(keys, ","))
		return fallback
	}
	return parsed
}

// envUint reads the first set unsigned environment variable, ignoring
// unparseable values.
func envUint(fallback uint, keys ...string) uint {
	value := envFirst(keys...)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		slog.Warn("ignoring unparseable environment variable", "keys", strings.Join(keys, ","))
		return fallback
	}
	return uint(parsed)
}
