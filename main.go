package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var version = "dev"

var insecureFlag bool

func main() {
	apiURL := flag.String("api-url", os.Getenv("TOWEROPS_API_URL"), "API URL (e.g., wss://towerops.net)")
	token := flag.String("token", os.Getenv("TOWEROPS_AGENT_TOKEN"), "Agent authentication token")
	tokenFile := flag.String("token-file", "", "Path to file containing agent token (preferred over --token)")
	logLevel := flag.String("log-level", envOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	flag.BoolVar(&insecureFlag, "insecure", false, "Allow plaintext ws:// connections (insecure)")
	flag.Parse()

	// Read token from file if --token-file is provided
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read token file: %v\n", err)
			os.Exit(1)
		}
		t := strings.TrimSpace(string(data))
		token = &t
	}

	// Warn if --token was used via CLI (visible in /proc/cmdline)
	if *tokenFile == "" && isFlagSet("token") {
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
	slog.SetDefault(slog.New(newColorHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *apiURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "error: --api-url and --token are required (or set TOWEROPS_API_URL and TOWEROPS_AGENT_TOKEN)")
		flag.Usage()
		os.Exit(1)
	}

	slog.Info("towerops agent starting", "version", version)

	// Convert HTTP(S) to WebSocket URL
	wsURL := toWebSocketURL(*apiURL)
	slog.Info("websocket url", "url", sanitizeURL(wsURL))

	// Signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Run agent with reconnect loop
	runAgent(ctx, wsURL, *token)

	slog.Info("towerops agent stopped")
}

// toWebSocketURL converts an HTTP(S) URL to a WebSocket URL.
// Rejects plaintext ws:// unless --insecure is set.
func toWebSocketURL(rawURL string) string {
	var result string
	switch {
	case strings.HasPrefix(rawURL, "http://"):
		result = "ws://" + strings.TrimPrefix(rawURL, "http://")
	case strings.HasPrefix(rawURL, "https://"):
		result = "wss://" + strings.TrimPrefix(rawURL, "https://")
	case strings.HasPrefix(rawURL, "ws://"), strings.HasPrefix(rawURL, "wss://"):
		result = rawURL
	default:
		result = "wss://" + rawURL
	}

	if strings.HasPrefix(result, "ws://") && !insecureFlag {
		slog.Error("plaintext ws:// connection rejected — use wss:// or pass --insecure to allow")
		os.Exit(1)
	}
	return result
}

// isFlagSet returns true if a flag was explicitly set on the command line.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// sanitizeURL masks query parameters to prevent credential leakage in logs.
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
	return u.String()
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
