# Towerops Agent

A lightweight Rust-based remote polling agent for Towerops SNMP monitoring.

## Overview

The Towerops agent enables customers to deploy SNMP polling infrastructure on their internal networks. The agent polls SNMP devices locally and reports metrics to the Towerops API using token-based authentication.

## Features

- **Local SNMP Polling**: Poll devices on your internal network without exposing them to the internet
- **Secure Communication**: All communication with Towerops API uses HTTPS with token authentication
- **Metric Buffering**: Stores up to 24 hours of metrics in SQLite when API is unavailable
- **Automatic Configuration**: Fetches polling configuration from the Towerops API
- **Low Resource Usage**: Built in Rust for minimal memory and CPU footprint (< 256 MB RAM typical)
- **Docker Ready**: Pre-built Docker images for easy deployment

## Quick Start

### Using Pre-built Image

Pull the latest image from GitLab Container Registry:

```bash
docker pull registry.gitlab.com/graham/towerops-agent:latest
```

### Using Docker Compose

1. Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  towerops-agent:
    image: registry.gitlab.com/graham/towerops-agent:latest
    restart: unless-stopped
    environment:
      - TOWEROPS_API_URL=https://app.towerops.com
      - TOWEROPS_AGENT_TOKEN=your-agent-token-here
    volumes:
      - ./data:/data
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
| `CONFIG_REFRESH_SECONDS` | How often to refresh configuration | 300 (5 minutes) |
| `DATABASE_PATH` | SQLite database path for buffering | `/data/towerops-agent.db` |

### Obtaining an Agent Token

1. Log in to your Towerops account
2. Navigate to your organization's Agents page
3. Click "Create New Agent"
4. Copy the token (it will only be shown once)

## Architecture

The agent consists of several components:

- **API Client**: Communicates with Towerops API to fetch configuration and submit metrics
- **SNMP Poller**: Polls configured devices for sensor readings and interface statistics
- **Storage Buffer**: SQLite database that buffers metrics during API outages
- **Scheduler**: Coordinates polling intervals and metric submission

### Polling Flow

1. Agent fetches configuration from API every 5 minutes (configurable)
2. For each equipment item, polls sensors and interfaces at configured intervals
3. Metrics are stored locally in SQLite
4. Every 30 seconds, pending metrics are submitted to the API
5. Successfully submitted metrics are marked as sent and cleaned up after 24 hours

### Buffering

If the API is unreachable, metrics are stored locally for up to 24 hours. When connectivity is restored, the agent automatically submits all buffered metrics.

## Building from Source

### Prerequisites

- Rust 1.82 or later (required for Cargo.lock v4)
- SQLite development libraries

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

### Agent Not Connecting

- Verify the API URL is correct
- Check that the agent token is valid and hasn't been revoked
- Ensure network connectivity to the Towerops API

### No Metrics Appearing

- Check that equipment is assigned to this agent in Towerops
- Verify SNMP credentials are correct in Towerops equipment settings
- Review agent logs for SNMP polling errors

### High Memory Usage

- Check the size of the SQLite database (`/data/towerops-agent.db`)
- Verify metrics are being submitted successfully (check API connectivity)

## Resource Requirements

- **Memory**: 128-256 MB typical, 512 MB maximum
- **CPU**: 0.1-0.5 cores typical
- **Disk**: ~100 MB for 24 hours of buffered metrics
- **Network**: Minimal (metrics are small JSON payloads)

## Security

- Agent token should be kept secret (treat like a password)
- All API communication uses HTTPS with certificate verification
- Agent requires no inbound network connections
- SNMP community strings are only used locally and never logged

## Development Status

**NOTE**: SNMP library integration is incomplete. The current implementation compiles but requires proper SNMP library integration for production use. This will be completed in the next development phase.

## License

Copyright © 2026 Towerops
