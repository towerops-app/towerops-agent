# Towerops Agent

A lightweight Rust-based remote polling agent for Towerops SNMP monitoring.

## Overview

The Towerops agent enables customers to deploy SNMP polling infrastructure on their internal networks. The agent connects to the Towerops server via WebSocket and executes SNMP queries as directed by the server.

## Features

- **Local SNMP Polling**: Poll devices on your internal network without exposing them to the internet
- **SNMP Trap Receiver**: Listen for SNMP v1 and v2c traps from network devices
- **Secure Communication**: All communication with Towerops uses WebSocket over TLS with token authentication
- **Real-time Updates**: Server pushes configuration changes instantly via persistent WebSocket connection
- **Automatic Reconnection**: Exponential backoff reconnection on network failures
- **Automatic Updates**: Checks for new versions hourly and self-updates when available (requires Docker socket access)
- **Low Resource Usage**: Built in Rust for minimal memory and CPU footprint (< 256 MB RAM typical)
- **Docker Ready**: Pre-built Docker images for easy deployment

## Quick Start

### Using Pre-built Image

Pull the latest image from Docker Hub:

```bash
docker pull ghcr.io/towerops-app/towerops-agent:latest
```

### Using Docker Compose

1. Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  towerops-agent:
    image: ghcr.io/towerops-app/towerops-agent:latest
    restart: unless-stopped
    # Required for ICMP ping health checks
    cap_add:
      - NET_RAW
    environment:
      - TOWEROPS_API_URL=https://towerops.net
      - TOWEROPS_AGENT_TOKEN=your-agent-token-here
      - LOG_LEVEL=info
      # Optional: Enable SNMP trap listener
      - TRAP_ENABLED=true
      - TRAP_PORT=162
    ports:
      # SNMP trap listener (UDP) - only needed if TRAP_ENABLED=true
      - "162:162/udp"
```

2. Start the agent:

```bash
docker-compose up -d
```

### Configuration

The agent is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TOWEROPS_API_URL` | Towerops API endpoint | Required |
| `TOWEROPS_AGENT_TOKEN` | Agent authentication token | Required |
| `LOG_LEVEL` | Logging level (error, warn, info, debug) | info |
| `TRAP_ENABLED` | Enable SNMP trap listener | false |
| `TRAP_PORT` | UDP port for SNMP traps | 162 |

### Obtaining an Agent Token

1. Log in to your Towerops account
2. Navigate to your organization's Agents page
3. Click "Create New Agent"
4. Copy the token (it will only be shown once)

## Architecture

The agent uses a WebSocket-based architecture for real-time communication:

- **WebSocket Client**: Maintains a persistent connection to the Towerops server
- **SNMP Executor**: Executes SNMP queries (GET, WALK) as directed by the server
- **Trap Listener**: Optional UDP listener for receiving SNMP traps from devices

### Communication Flow

1. Agent establishes WebSocket connection to `{api_url}/socket/agent/websocket`
2. Agent authenticates by joining PubSub channel with token
3. Server pushes SNMP jobs (queries to execute) to agent
4. Agent executes queries and sends results back via WebSocket
5. Periodic heartbeats maintain connection health
6. On disconnect, agent reconnects with exponential backoff (1s to 60s)

### SNMP Trap Listener

When enabled (`TRAP_ENABLED=true`), the agent listens for SNMP traps:

- Supports SNMPv1 and SNMPv2c trap formats
- Logs received traps with source address, enterprise OID, and variable bindings
- Default port 162 (standard SNMP trap port)

## Building from Source

### Prerequisites

- Rust 1.91 or later

### Build

```bash
cargo build --release
```

The binary will be in `target/release/towerops-agent`.

### Docker Build

```bash
docker build -t towerops-agent .
```

## Troubleshooting

### Agent Crashes with Segmentation Fault (Exit Code 139)

This typically occurs when the container doesn't have the `NET_RAW` capability required for ICMP ping:

```yaml
cap_add:
  - NET_RAW
```

Add this to your `docker-compose.yml` under the agent service. Without this capability, the agent will crash when attempting health checks.

### Agent Not Connecting

- Verify the API URL is correct (accepts http://, https://, ws://, or wss://)
- Check that the agent token is valid and hasn't been revoked
- Ensure network connectivity to the Towerops API
- Check logs for connection errors: `docker logs towerops-agent`

### No Metrics Appearing

- Check that equipment is assigned to this agent in Towerops
- Verify SNMP credentials are correct in Towerops equipment settings
- Review agent logs for SNMP polling errors
- Ensure the agent is connected (check Towerops UI for agent status)

### Traps Not Received

- Ensure `TRAP_ENABLED=true` is set
- Verify UDP port 162 is exposed and not blocked by firewall
- Check that devices are configured to send traps to the agent's IP
- Look for trap messages in logs with `LOG_LEVEL=debug`

## Resource Requirements

- **Memory**: 64-128 MB typical, 256 MB maximum
- **CPU**: 0.1-0.5 cores typical
- **Network**: Minimal (small protobuf messages over WebSocket)

## Security

- Agent token should be kept secret (treat like a password)
- All API communication uses TLS with certificate verification
- Agent requires no inbound network connections (except optional trap listener on UDP 162)
- SNMP community strings are only used locally and never logged

## License

Copyright 2026 Towerops
