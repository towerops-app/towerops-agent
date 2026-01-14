# Towerops Agent - User Guide

Complete guide for deploying and managing Towerops remote SNMP polling agents.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Methods](#deployment-methods)
- [Configuration](#configuration)
- [Network Requirements](#network-requirements)
- [Monitoring & Troubleshooting](#monitoring--troubleshooting)
- [Upgrades & Maintenance](#upgrades--maintenance)

## Overview

The Towerops agent is a lightweight Rust application that runs on your network to perform local SNMP polling. It connects to the Towerops API via HTTPS to receive configuration and submit metrics.

**Benefits**:
- Poll devices behind firewalls without exposing them to the internet
- Reduced latency for SNMP polling
- Automatic failover with 24-hour metric buffering
- Minimal resource footprint (<50 MB RAM, <20 MB disk)

## Prerequisites

### System Requirements

- **CPU**: 1 core (shared acceptable)
- **RAM**: 256 MB minimum, 512 MB recommended
- **Disk**: 1 GB minimum for logs and database
- **Network**: Outbound HTTPS (443) to Towerops API

### Supported Platforms

- **Docker/Podman**: Linux (amd64, arm64)
- **Kubernetes**: Deployments supported
- **Bare Metal**: Linux (amd64, arm64)

### Before You Start

1. **Create Agent Token** in Towerops UI:
   - Navigate to Organization Settings > Agents
   - Click "Create New Agent"
   - Copy the token (shown only once)
   - Save securely (e.g., password manager)

2. **Assign Equipment** to agent:
   - Via Equipment form: Select agent in "Remote Agent" dropdown
   - Via Site form: Set site default agent
   - Via Organization form: Set organization default agent

## Quick Start

### Docker Compose (Recommended)

1. **Create `docker-compose.yml`**:
```yaml
version: '3.8'

services:
  towerops-agent:
    image: registry.gitlab.com/towerops/towerops-agent:latest
    container_name: towerops-agent
    restart: unless-stopped

    environment:
      # Required
      TOWEROPS_API_URL: https://app.towerops.com
      TOWEROPS_AGENT_TOKEN: "your-agent-token-here"

      # Optional
      CONFIG_REFRESH_SECONDS: "300"  # 5 minutes
      DATABASE_PATH: "/data/towerops-agent.db"
      RUST_LOG: "info"

    volumes:
      - ./data:/data

    # Allow access to local network for SNMP
    network_mode: "host"

    # Health check
    healthcheck:
      test: ["CMD", "test", "-f", "/data/towerops-agent.db"]
      interval: 30s
      timeout: 10s
      retries: 3
```

2. **Start the agent**:
```bash
docker-compose up -d
```

3. **Verify it's running**:
```bash
docker-compose logs -f towerops-agent
```

You should see:
```
INFO towerops_agent: Towerops agent starting
INFO towerops_agent: API URL: https://app.towerops.com
INFO towerops_agent: Refreshing configuration from API
INFO towerops_agent: Configuration updated: 5 equipment items
```

## Deployment Methods

### Method 1: Docker Run

```bash
docker run -d \
  --name towerops-agent \
  --restart unless-stopped \
  --network host \
  -e TOWEROPS_API_URL=https://app.towerops.com \
  -e TOWEROPS_AGENT_TOKEN="your-token-here" \
  -v ./data:/data \
  registry.gitlab.com/towerops/towerops-agent:latest
```

### Method 2: Podman

```bash
podman run -d \
  --name towerops-agent \
  --restart unless-stopped \
  --network host \
  -e TOWEROPS_API_URL=https://app.towerops.com \
  -e TOWEROPS_AGENT_TOKEN="your-token-here" \
  -v ./data:/data \
  registry.gitlab.com/towerops/towerops-agent:latest
```

### Method 3: Kubernetes

Create `towerops-agent-deployment.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: towerops

---
apiVersion: v1
kind: Secret
metadata:
  name: towerops-agent-token
  namespace: towerops
type: Opaque
stringData:
  token: "your-agent-token-here"

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: towerops-agent-data
  namespace: towerops
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: towerops-agent
  namespace: towerops
spec:
  replicas: 1
  selector:
    matchLabels:
      app: towerops-agent
  template:
    metadata:
      labels:
        app: towerops-agent
    spec:
      hostNetwork: true  # Required for local SNMP polling
      containers:
      - name: agent
        image: registry.gitlab.com/towerops/towerops-agent:latest
        env:
        - name: TOWEROPS_API_URL
          value: "https://app.towerops.com"
        - name: TOWEROPS_AGENT_TOKEN
          valueFrom:
            secretKeyRef:
              name: towerops-agent-token
              key: token
        - name: RUST_LOG
          value: "info"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: towerops-agent-data
```

Apply:
```bash
kubectl apply -f towerops-agent-deployment.yaml
```

### Method 4: Systemd Service (Bare Metal)

1. **Download binary**:
```bash
# For amd64
wget https://github.com/towerops/towerops-agent/releases/latest/download/towerops-agent-linux-amd64 -O /usr/local/bin/towerops-agent

# For arm64
wget https://github.com/towerops/towerops-agent/releases/latest/download/towerops-agent-linux-arm64 -O /usr/local/bin/towerops-agent

chmod +x /usr/local/bin/towerops-agent
```

2. **Create service file** `/etc/systemd/system/towerops-agent.service`:
```ini
[Unit]
Description=Towerops Remote SNMP Polling Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=towerops
Group=towerops
Restart=always
RestartSec=10

Environment=TOWEROPS_API_URL=https://app.towerops.com
Environment=TOWEROPS_AGENT_TOKEN=your-token-here
Environment=DATABASE_PATH=/var/lib/towerops-agent/towerops-agent.db
Environment=RUST_LOG=info

ExecStart=/usr/local/bin/towerops-agent \
  --api-url ${TOWEROPS_API_URL} \
  --token ${TOWEROPS_AGENT_TOKEN} \
  --database-path ${DATABASE_PATH}

[Install]
WantedBy=multi-user.target
```

3. **Create user and directories**:
```bash
useradd -r -s /bin/false towerops
mkdir -p /var/lib/towerops-agent
chown towerops:towerops /var/lib/towerops-agent
```

4. **Start service**:
```bash
systemctl daemon-reload
systemctl enable towerops-agent
systemctl start towerops-agent
systemctl status towerops-agent
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TOWEROPS_API_URL` | Yes | - | Towerops API endpoint |
| `TOWEROPS_AGENT_TOKEN` | Yes | - | Agent authentication token |
| `CONFIG_REFRESH_SECONDS` | No | 300 | How often to fetch config (5 min) |
| `DATABASE_PATH` | No | `/data/towerops-agent.db` | SQLite database location |
| `RUST_LOG` | No | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |

### Command Line Arguments

```bash
towerops-agent \
  --api-url https://app.towerops.com \
  --token YOUR_TOKEN_HERE \
  --config-refresh-seconds 300 \
  --database-path /data/towerops-agent.db
```

All environment variables can be overridden by command-line arguments.

### Agent Behavior

The agent operates on several independent timers:

- **Config Refresh**: Every 5 minutes (configurable)
  - Fetches list of equipment to poll
  - Updates sensor and interface configurations

- **Equipment Polling**: Per-equipment interval (default 60s)
  - Each device polls independently
  - Respects `check_interval_seconds` from API

- **Metrics Flush**: Every 30 seconds
  - Submits up to 100 pending metrics
  - Retries on API failure

- **Heartbeat**: Every 60 seconds
  - Updates agent status in UI
  - Includes version, hostname, uptime

- **Cleanup**: Every hour
  - Removes metrics older than 24 hours
  - Prevents database growth

## Network Requirements

### Firewall Rules

**Outbound** (from agent):
- `TCP 443` (HTTPS) to Towerops API
  - `app.towerops.com` or your self-hosted instance
  - Required for: config, metrics, heartbeat

**Inbound** (to local network):
- `UDP 161` (SNMP) to devices being monitored
  - Must reach all equipment assigned to this agent
  - No inbound connections to agent itself

### DNS Requirements

- Agent must resolve `app.towerops.com` (or your API hostname)
- If using internal DNS, ensure agent has access

### Proxy Support

If deploying behind HTTP proxy:

```bash
# Docker
docker run -d \
  -e HTTP_PROXY=http://proxy.example.com:8080 \
  -e HTTPS_PROXY=http://proxy.example.com:8080 \
  -e NO_PROXY=localhost,127.0.0.1 \
  ...

# Systemd
Environment=HTTP_PROXY=http://proxy.example.com:8080
Environment=HTTPS_PROXY=http://proxy.example.com:8080
```

### Network Topology Examples

**Scenario 1: Single Network**
```
Internet ← HTTPS → [Towerops Agent] ← UDP 161 → [Network Devices]
```

**Scenario 2: DMZ + Internal**
```
Internet ← HTTPS → [Firewall] → [DMZ: Agent] ← UDP 161 → [Internal Devices]
                                     ↓
                               (Allow outbound HTTPS)
```

**Scenario 3: Multiple VLANs**
```
Internet ← HTTPS → [Agent on Management VLAN]
                        ↓ UDP 161
                   [VLAN 10 Devices]
                   [VLAN 20 Devices]
                   [VLAN 30 Devices]
```
*Agent needs routing to all device VLANs*

## Monitoring & Troubleshooting

### Health Checks

**1. Check Agent Status in UI**:
- Navigate to Organization > Agents
- Look for "Last Seen" timestamp (should be <2 minutes)
- Check "Equipment Count"

**2. Check Container/Service Status**:
```bash
# Docker
docker ps | grep towerops-agent
docker logs towerops-agent

# Podman
podman ps | grep towerops-agent
podman logs towerops-agent

# Kubernetes
kubectl get pods -n towerops
kubectl logs -n towerops deployment/towerops-agent

# Systemd
systemctl status towerops-agent
journalctl -u towerops-agent -f
```

**3. Check Database**:
```bash
# View database size (should be <100 MB)
ls -lh /path/to/towerops-agent.db

# Count pending metrics
sqlite3 /path/to/towerops-agent.db "SELECT COUNT(*) FROM metrics WHERE sent = 0;"
```

### Common Issues

#### Agent Shows Offline

**Symptom**: "Last Seen" is >5 minutes ago

**Causes**:
1. Agent container/service stopped
2. Network connectivity to API failed
3. Token was revoked

**Resolution**:
```bash
# Check if running
docker ps | grep towerops
systemctl status towerops-agent

# Check logs for errors
docker logs towerops-agent | tail -50

# Test API connectivity
curl -H "Authorization: Bearer YOUR_TOKEN" https://app.towerops.com/api/v1/agent/config
```

#### No Metrics Appearing

**Symptom**: Equipment shows no recent data

**Causes**:
1. Equipment not assigned to agent
2. SNMP community string incorrect
3. Firewall blocking UDP 161
4. Device not responding to SNMP

**Resolution**:
```bash
# Check agent config
docker logs towerops-agent | grep "Configuration updated"
# Should show equipment count > 0

# Test SNMP manually from agent host
snmpget -v2c -c public DEVICE_IP 1.3.6.1.2.1.1.3.0

# Check for SNMP errors in logs
docker logs towerops-agent | grep "SNMP"
```

#### High Memory Usage

**Symptom**: Agent using >512 MB RAM

**Causes**:
1. Too many devices for one agent
2. Metrics not being sent (database growing)
3. Memory leak (rare)

**Resolution**:
```bash
# Check database size
docker exec towerops-agent ls -lh /data/towerops-agent.db

# Check pending metrics
docker exec towerops-agent sqlite3 /data/towerops-agent.db "SELECT COUNT(*) FROM metrics WHERE sent = 0;"

# If database is large (>100 MB), restart agent (will cleanup old metrics)
docker restart towerops-agent
```

#### Metrics Delayed

**Symptom**: Data appears 5-10 minutes late

**Causes**:
1. API connectivity issues
2. Database too large
3. Agent overloaded

**Resolution**:
```bash
# Check for API errors
docker logs towerops-agent | grep "Failed to submit metrics"

# Check metric submission rate
docker logs towerops-agent | grep "Successfully submitted"

# Reduce polling frequency in UI if needed
```

### Log Levels

For debugging, increase log verbosity:

```bash
# Docker/Podman
docker run -e RUST_LOG=debug ...
podman run -e RUST_LOG=debug ...

# Kubernetes
kubectl set env deployment/towerops-agent RUST_LOG=debug -n towerops

# Systemd
vi /etc/systemd/system/towerops-agent.service
# Change: Environment=RUST_LOG=debug
systemctl daemon-reload
systemctl restart towerops-agent
```

Log levels:
- `error`: Only critical errors
- `warn`: Warnings and errors
- `info`: Normal operation (default)
- `debug`: Verbose debugging
- `trace`: Very verbose (includes SNMP PDUs)

## Upgrades & Maintenance

### Upgrading

**Docker**:
```bash
# Pull latest image
docker pull registry.gitlab.com/towerops/towerops-agent:latest

# Restart with new image
docker-compose down
docker-compose up -d

# Or without compose
docker stop towerops-agent
docker rm towerops-agent
docker run -d ... registry.gitlab.com/towerops/towerops-agent:latest
```

**Podman**:
```bash
podman pull registry.gitlab.com/towerops/towerops-agent:latest
podman stop towerops-agent
podman rm towerops-agent
podman run -d ... registry.gitlab.com/towerops/towerops-agent:latest
```

**Kubernetes**:
```bash
kubectl set image deployment/towerops-agent \
  agent=registry.gitlab.com/towerops/towerops-agent:latest \
  -n towerops
```

**Systemd**:
```bash
# Download new binary
wget https://github.com/towerops/towerops-agent/releases/latest/download/towerops-agent-linux-amd64 \
  -O /usr/local/bin/towerops-agent.new

# Verify and replace
chmod +x /usr/local/bin/towerops-agent.new
mv /usr/local/bin/towerops-agent.new /usr/local/bin/towerops-agent

# Restart service
systemctl restart towerops-agent
```

### Backup & Recovery

**Backup**:
```bash
# Database only (recommended)
cp /data/towerops-agent.db /backup/towerops-agent-$(date +%Y%m%d).db

# Or entire data directory
tar czf towerops-agent-backup-$(date +%Y%m%d).tar.gz /data/
```

**Recovery**:
```bash
# Stop agent
docker stop towerops-agent

# Restore database
cp /backup/towerops-agent-YYYYMMDD.db /data/towerops-agent.db

# Start agent
docker start towerops-agent
```

**Database Corruption**:
If database is corrupted, agent will automatically rebuild it on next start. You'll lose buffered metrics but no configuration.

### Scaling

**One Agent, Many Devices**:
- Single agent can handle 100+ devices
- Monitor memory (<512 MB) and database size (<100 MB)
- Adjust poll intervals if needed

**Multiple Agents**:
- Deploy one agent per site/network
- Assign equipment to appropriate agent via UI
- Each agent operates independently
- No coordination needed between agents

### Uninstalling

**Docker**:
```bash
docker-compose down -v  # -v removes volumes
docker rmi registry.gitlab.com/towerops/towerops-agent
```

**Podman**:
```bash
podman stop towerops-agent
podman rm towerops-agent
podman rmi registry.gitlab.com/towerops/towerops-agent
```

**Kubernetes**:
```bash
kubectl delete namespace towerops
```

**Systemd**:
```bash
systemctl stop towerops-agent
systemctl disable towerops-agent
rm /etc/systemd/system/towerops-agent.service
rm /usr/local/bin/towerops-agent
rm -rf /var/lib/towerops-agent
userdel towerops
```

**In Towerops UI**:
- Navigate to Organization > Agents
- Click "Revoke" on the agent
- Reassign equipment to cloud polling or different agent

## Best Practices

1. **One Agent Per Network Segment**: Deploy agents close to devices for minimum latency
2. **Use Descriptive Names**: Name agents by location (e.g., "DC1-Core-Agent", "Branch-NYC-Agent")
3. **Monitor Agent Health**: Check "Last Seen" daily, set up alerts for offline agents
4. **Start Small**: Deploy with 5-10 devices, verify, then scale
5. **Regular Updates**: Update agents quarterly or when security patches released
6. **Backup Tokens**: Store agent tokens securely (password manager, vault)
7. **Log Rotation**: Ensure Docker/systemd logs don't fill disk

## Security Considerations

- **Token Security**: Treat agent tokens like passwords, never commit to git
- **Network Isolation**: Agent only needs outbound HTTPS, no inbound
- **Minimal Permissions**: Run as non-root user (Docker image does this)
- **Token Rotation**: Revoke and recreate tokens annually or on compromise
- **HTTPS Only**: Agent always uses TLS for API communication

## Support

**Documentation**:
- Main README: `towerops-agent/README.md`
- Architecture: `AGENT_IMPLEMENTATION.md`
- Next Steps: `AGENT_NEXT_STEPS.md`

**Getting Help**:
- Check logs for error messages
- Review troubleshooting section above
- Contact Towerops support with:
  - Agent version (`docker logs towerops-agent | grep version`)
  - Error logs (last 50 lines)
  - Network diagram
  - Number of devices being polled
