# Towerops Agent - Development Notes

This file provides context for Claude Code when working on the Rust agent.

## Project Overview

Lightweight Rust agent for remote SNMP polling. Deployed on customer networks to poll local SNMP devices and report metrics to Towerops API via HTTPS.

## What's Complete ✅

### Architecture & Design
- [x] Complete module structure (12 source files)
- [x] Configuration types matching Phoenix API responses
- [x] Metric types (SensorReading, InterfaceStat) with proper serialization
- [x] Event loop with 5 concurrent tasks (tokio::select!)
- [x] SQLite buffering with 24-hour retention
- [x] Error types and result handling throughout

### Core Functionality
- [x] **API Client** (`api_client.rs`)
  - fetch_config() - GET /api/v1/agent/config (Protocol Buffers)
  - submit_metrics() - POST /api/v1/agent/metrics (Protocol Buffers)
  - heartbeat() - POST /api/v1/agent/heartbeat (Protocol Buffers)
  - Uses ureq with rustls-tls (30s timeout)
  - Full Protocol Buffers integration for all endpoints

- [x] **Storage** (`buffer/storage.rs`)
  - store_metric() - Save metrics to SQLite
  - get_pending_metrics() - Retrieve unsent metrics
  - mark_metrics_sent() - Track submission
  - cleanup_old_metrics() - Remove old data
  - Last poll time tracking per equipment

- [x] **Scheduler** (`poller/scheduler.rs`)
  - Config refresh every 5 minutes
  - Metrics flush every 30 seconds
  - Heartbeat every 60 seconds
  - Cleanup every hour
  - Poll check every 5 seconds

- [x] **Executor** (`poller/executor.rs`)
  - poll_sensors() - Poll configured sensors
  - poll_interfaces() - Poll interface statistics
  - Parallel polling with tokio::join!
  - Applies sensor divisors

- [x] **Main** (`main.rs`)
  - CLI with clap (--api-url, --token, etc.)
  - Environment variable support
  - Logging with tracing
  - Graceful startup/shutdown
  - Docker image version checking on startup

- [x] **Version Checking** (`version.rs`)
  - Checks Docker Hub for newer image versions on startup
  - Compares current version with latest available
  - Logs warnings if updates are available
  - Non-blocking, fails gracefully if Docker Hub unavailable

### Protocol Buffers Integration
- [x] **Protobuf Definitions** (`proto/agent.proto`)
  - AgentConfig, Equipment, SnmpConfig, Sensor, Interface
  - MetricBatch, Metric, SensorReading, InterfaceStat
  - HeartbeatMetadata, HeartbeatResponse
- [x] **Code Generation** (`build.rs`)
  - Uses prost-build to compile protobuf definitions
  - Generates Rust types at build time
- [x] **API Communication**
  - Config endpoint: Accepts `application/x-protobuf`, decodes response
  - Metrics endpoint: Encodes batch to protobuf, sends with proper content-type
  - Heartbeat endpoint: Encodes metadata to protobuf
  - Conversion functions between protobuf and internal types

### Build & Deployment
- [x] Cargo.toml with optimized release profile
  - opt-level = "z"
  - lto = true
  - codegen-units = 1
  - strip = true
- [x] Multi-stage Dockerfile (Alpine, ~10-20 MB)
- [x] docker-compose.example.yml
- [x] README with user documentation
- [x] .gitignore and .dockerignore
- [x] GitLab CI/CD configured for Docker Hub

### Build Status
```bash
✅ cargo build --release - SUCCESS
✅ cargo clippy - 0 warnings, 0 errors
📦 Target size optimized for minimal footprint
🚀 Protobuf integration complete
```

## Testing Gaps

- [ ] Unit tests for SNMP client
- [ ] Unit tests for storage (SQLite operations)
- [ ] Unit tests for API client (mock server)
- [ ] Integration test with real SNMP device

## Development Workflow

### Quick Start

1. **Build the agent**:
```bash
cargo build --release
```

2. **Run locally** (needs Phoenix backend running):
```bash
cargo run -- \
  --api-url http://localhost:4000 \
  --token <get-from-ui> \
  --database-path ./test.db
```

3. **Watch logs**:
```bash
RUST_LOG=debug cargo run -- ...
```

### Testing Changes

1. **Check compilation**:
```bash
cargo check
```

2. **Run tests**:
```bash
cargo test
```

3. **Format code**:
```bash
cargo fmt
```

4. **Check for issues**:
```bash
cargo clippy
```

### Docker Testing

1. **Build image**:
```bash
docker build -t towerops-agent:test .
```

2. **Run container**:
```bash
docker run --rm \
  -e TOWEROPS_API_URL=http://host.docker.internal:4000 \
  -e TOWEROPS_AGENT_TOKEN=<token> \
  -e RUST_LOG=info \
  -v $(pwd)/data:/data \
  towerops-agent:test
```

### CI/CD Pipeline

**Automated builds** via GitLab CI (`.gitlab-ci.yml`):
- Push to branch → test + build with branch tag
- Push to main → test + build + tag as `latest`
- Create tag (e.g., `v0.1.0`) → test + build + release

**Registry**: `registry.gitlab.com/towerops/towerops-agent`

**See**: `DEPLOYMENT.md` for complete CI/CD documentation

## Integration with Phoenix Backend

### API Endpoints (from agent perspective)

**GET /api/v1/agent/config**
- Headers: `Authorization: Bearer <token>`
- Response: Equipment list with sensors and interfaces
- Called every 5 minutes

**POST /api/v1/agent/metrics**
- Headers: `Authorization: Bearer <token>`
- Body: `{"metrics": [...]}`
- Response: `{"status": "accepted", "received": N}`
- Called every 30 seconds with pending metrics

**POST /api/v1/agent/heartbeat**
- Headers: `Authorization: Bearer <token>`
- Body: `{"version": "0.1.0", "hostname": "...", "uptime_seconds": 3600}`
- Response: `{"status": "ok"}`
- Called every 60 seconds

### Getting a Test Token

1. Start Phoenix: `mix phx.server`
2. Navigate to: `http://localhost:4000/orgs/:slug/agents`
3. Click "Create New Agent"
4. Copy the token (shown only once)
5. Use in agent: `--token <copied-token>`

## Architecture Decisions

### Why Tokio?
- Async event loop for efficient I/O
- Multiple concurrent timers (config, metrics, heartbeat)
- Non-blocking SNMP operations via spawn_blocking

### Why SQLite?
- Embedded, no external dependencies
- Persist metrics during API outages
- Small footprint (~100 MB for 24h of metrics)
- No configuration needed

### Why Rust?
- Small binary size (~10-20 MB with Alpine)
- Low memory usage (<256 MB typical)
- Cross-compile to multiple architectures
- Strong type safety for reliability

### Why Async SNMP with spawn_blocking?
- SNMP crate uses synchronous I/O
- spawn_blocking moves sync operations to thread pool
- Keeps main event loop non-blocking
- Allows concurrent polling without blocking other tasks

## Common Issues

### "Failed to fetch config" Error
**Check**:
1. Is Phoenix backend running?
2. Is the token valid (not revoked)?
3. Is the API URL correct?
4. Is there network connectivity?

### High Memory Usage
**Check**:
1. Database size: `ls -lh /data/towerops-agent.db`
2. Are metrics being submitted? (check logs)
3. Is cleanup running? (should see log every hour)

### Agent Not Showing as Online
**Check**:
1. Is heartbeat working? (check Phoenix logs)
2. Check `last_seen_at` in database: `SELECT last_seen_at FROM agent_tokens WHERE token_hash = ...`
3. Time sync between agent and server

## File Organization

```
towerops-agent/
├── src/
│   ├── main.rs              # Entry point, CLI, initialization
│   ├── config.rs            # Types matching API responses
│   ├── api_client.rs        # HTTP client for Towerops API
│   ├── version.rs           # Docker image version checking
│   ├── metrics/
│   │   └── mod.rs          # Metric types (SensorReading, InterfaceStat)
│   ├── snmp/
│   │   ├── mod.rs          # Module exports
│   │   ├── client.rs       # ✅ SNMP client (GET and WALK)
│   │   └── types.rs        # SNMP types and errors
│   ├── buffer/
│   │   ├── mod.rs          # Module exports
│   │   └── storage.rs      # SQLite buffering
│   └── poller/
│       ├── mod.rs          # Module exports
│       ├── executor.rs     # Poll execution logic
│       └── scheduler.rs    # Main event loop
├── Cargo.toml              # Dependencies and build config
├── Dockerfile              # Multi-stage build
├── README.md               # User documentation
└── CLAUDE.md              # This file
```

## Dependencies

**Key Crates**:
- `tokio` - Async runtime with full features
- `reqwest` - HTTP client (rustls-tls, no default features)
- `rusqlite` - SQLite (bundled)
- `serde` + `serde_json` - Serialization
- `snmp` - SNMP operations (v0.2) ⚠️ needs integration
- `tracing` + `tracing-subscriber` - Logging
- `clap` - CLI argument parsing
- `chrono` - Timestamps
- `anyhow` + `thiserror` - Error handling
- `hostname` - Get system hostname

## Next Actions

**Immediate** (for production readiness):
1. Add more comprehensive unit tests
2. Integration test with mock SNMP device
3. Load test with 100 devices
4. Stability test (7+ days continuous)

**Long-term** (nice to have):
1. SNMPv3 support
2. Agent-side threshold filtering
3. Configurable sampling rates
4. Agent health metrics endpoint

## Resources

- **Main Implementation Doc**: `/Users/graham/dev/towerops/AGENT_IMPLEMENTATION.md`
- **Next Steps Guide**: `/Users/graham/dev/towerops/AGENT_NEXT_STEPS.md`
- **SNMP Crate Docs**: https://docs.rs/snmp/0.2.2/snmp/
- **SNMP Crate Source**: https://github.com/hroi/snmp-rs

## Success Criteria

Agent is production-ready when:
- [x] Compiles successfully
- [x] Docker image builds
- [x] API client works (config, metrics, heartbeat)
- [x] SQLite buffering works
- [x] Event loop runs without panics
- [x] **SNMP polling works**
- [ ] **Integration testing complete** ← CURRENT FOCUS
- [ ] Metrics appear in Phoenix database
- [ ] Survives 24h API outage
- [ ] Uses <256 MB memory with 50 devices
- [ ] Runs for 7+ days without issues

## Notes for Future Development

### Adding New Metric Types
1. Add variant to `Metric` enum in `src/metrics/mod.rs`
2. Update `metric_type()` and `timestamp()` methods
3. Update Phoenix API to accept new type
4. Add serialization test

### Adding New Configuration Fields
1. Update structs in `src/config.rs`
2. Update Phoenix API `build_equipment_config/1`
3. Consider backwards compatibility

### Debugging SNMP Issues
- Set `RUST_LOG=debug` to see all SNMP operations
- Check IP reachability: `ping <device-ip>`
- Test SNMP manually: `snmpget -v2c -c public <device-ip> <oid>`
- Verify community string is correct
- Check firewall rules (UDP port 161)

---

**Last Updated**: January 14, 2026
**Status**: All code complete, integration testing needed
**Version**: 0.1.0 (pre-release)
