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

var insecureFlag bool

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
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
	logLevel := fs.String("log-level", envOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	logFormat := fs.String("log-format", envOrDefault("LOG_FORMAT", "text"), "Log output format (text, json)")
	fs.BoolVar(&insecureFlag, "insecure", false, "Allow plaintext ws:// connections (insecure)")
	trapEnabled := fs.Bool("trap-enabled", envBool("TRAP_ENABLED", false), "Listen for SNMP traps")
	trapPort := fs.Uint("trap-port", envUint("TRAP_PORT", 162), "UDP port for the SNMP trap listener")
	trapCommunity := fs.String("trap-community", os.Getenv("TRAP_COMMUNITY"), "Only accept traps carrying this community string (default: any)")

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

	// Setup structured logging
	var level slog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(newLogHandler(os.Stderr, level, *logFormat)))

	if *apiURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "error: --api-url and --token are required (or set TOWEROPS_API_URL and TOWEROPS_AGENT_TOKEN)")
		fs.Usage()
		return 1
	}

	slog.Info("towerops agent starting", "version", version, "built", buildDate)

	// Convert HTTP(S) to WebSocket URL
	wsURL, err := toWebSocketURL(*apiURL, insecureFlag)
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
		listener, err := startTrapListener(uint16(*trapPort), *trapCommunity)
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
			result = "wss://" + rawURL
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

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool reads a boolean environment variable, ignoring unparseable values.
func envBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(envOrDefault(key, strconv.FormatBool(fallback)))
	if err != nil {
		slog.Warn("ignoring unparseable environment variable", "key", key)
		return fallback
	}
	return v
}

// envUint reads an unsigned environment variable, ignoring unparseable values.
func envUint(key string, fallback uint) uint {
	v, err := strconv.ParseUint(envOrDefault(key, strconv.FormatUint(uint64(fallback), 10)), 10, 32)
	if err != nil {
		slog.Warn("ignoring unparseable environment variable", "key", key)
		return fallback
	}
	return uint(v)
}
