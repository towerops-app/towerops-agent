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

func main() {
	apiURL := flag.String("api-url", os.Getenv("TOWEROPS_API_URL"), "API URL (e.g., wss://towerops.net)")
	token := flag.String("token", os.Getenv("TOWEROPS_AGENT_TOKEN"), "Agent authentication token")
	logLevel := flag.String("log-level", envOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	flag.Parse()

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
func toWebSocketURL(url string) string {
	switch {
	case strings.HasPrefix(url, "http://"):
		return "ws://" + strings.TrimPrefix(url, "http://")
	case strings.HasPrefix(url, "https://"):
		return "wss://" + strings.TrimPrefix(url, "https://")
	case strings.HasPrefix(url, "ws://"), strings.HasPrefix(url, "wss://"):
		return url
	default:
		return "wss://" + url
	}
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
