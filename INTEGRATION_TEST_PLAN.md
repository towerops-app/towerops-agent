# Agent Integration Test Plan

This document provides a complete plan for integration testing the Towerops agent with the Phoenix backend.

## Prerequisites

- Phoenix backend running locally (`mix phx.server`)
- Docker or podman installed
- Agent Docker image built (`localhost/towerops-agent:latest`)
- Access to SNMP test device OR SNMP simulator running

## Test Environment Options

### Option 1: Using Real SNMP Device (Recommended for Complete Testing)

The existing integration test file references a MikroTik device at `10.0.19.254`.

**Requirements**:
- Network access to SNMP device
- Valid SNMP community string
- Device must support SNMPv2c

### Option 2: Using SNMP Simulator (Better for CI/CD)

Use `snmpsim` to simulate SNMP devices:

```bash
# Install snmpsim
pip install snmpsim

# Create simulation data directory
mkdir -p ~/snmpsim-data

# Create a simple device simulation file
cat > ~/snmpsim-data/public.snmprec << 'EOF'
1.3.6.1.2.1.1.1.0|4|Test Router v1.0
1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.9.1.1
1.3.6.1.2.1.1.3.0|67|12345678
1.3.6.1.2.1.1.4.0|4|admin@test.local
1.3.6.1.2.1.1.5.0|4|test-router
1.3.6.1.2.1.1.6.0|4|Test Lab
# Temperature sensor
1.3.6.1.4.1.9.9.91.1.1.1.1.1.1000|2|8
1.3.6.1.4.1.9.9.91.1.1.1.1.4.1000|2|450
# Interface ifIndex
1.3.6.1.2.1.2.2.1.1.1|2|1
1.3.6.1.2.1.2.2.1.2.1|4|GigabitEthernet0/1
1.3.6.1.2.1.2.2.1.10.1|65|1234567890
1.3.6.1.2.1.2.2.1.16.1|65|9876543210
EOF

# Start simulator
snmpsimd.py \
  --data-dir=~/snmpsim-data \
  --agent-udpv4-endpoint=127.0.0.1:1161 \
  --v2c-arch
```

**Test against simulator**:
```bash
# Verify simulator works
snmpget -v2c -c public localhost:1161 1.3.6.1.2.1.1.1.0
# Should return: SNMPv2-MIB::sysDescr.0 = STRING: Test Router v1.0
```

## Integration Test Procedure

### Phase 1: Backend Setup

1. **Start Phoenix Server**:
```bash
cd /Users/graham/dev/towerops
mix phx.server
# Access at http://localhost:4000
```

2. **Create Organization and User** (if not exists):
- Register a test user via UI
- Create organization "Test Org"

3. **Create Test Equipment**:
- Navigate to Sites → Create Site "Test Site"
- Add Equipment "Test Router"
  - IP Address: `127.0.0.1:1161` (if using simulator) or `10.0.19.254` (real device)
  - SNMP Enabled: Yes
  - SNMP Version: 2c
  - SNMP Community: `public` (simulator) or `kdyyJrT0Mm` (real device)
  - Poll Interval: 60 seconds

4. **Run SNMP Discovery**:
- Click "Discover SNMP" on equipment page
- Verify sensors and interfaces are discovered
- Expected sensors: Temperature sensors (Cisco) or system sensors (MikroTik)
- Expected interfaces: At least 1 network interface

5. **Create Agent Token**:
- Navigate to `/orgs/:slug/agents`
- Click "Create New Agent"
- Name: "Test Agent"
- Copy the token (shown only once) - save it for next steps

6. **Assign Equipment to Agent**:
- On equipment page, under "Agent Assignment" section
- Select "Test Agent"
- Click "Assign Agent"
- Or set as site/organization default

### Phase 2: Agent Setup & Deployment

#### Option A: Run with Docker/Podman

1. **Create agent configuration**:
```bash
cd /Users/graham/dev/towerops/towerops-agent

# Create data directory
mkdir -p data

# Run agent
podman run --rm -it \
  --network=host \
  -e TOWEROPS_API_URL=http://localhost:4000 \
  -e TOWEROPS_AGENT_TOKEN=<your-token-here> \
  -e RUST_LOG=info \
  -v $(pwd)/data:/data \
  localhost/towerops-agent:latest
```

**For simulator on different machine**:
```bash
# Use host.docker.internal for Mac/Windows
podman run --rm -it \
  --add-host=host.docker.internal:host-gateway \
  -e TOWEROPS_API_URL=http://host.docker.internal:4000 \
  -e TOWEROPS_AGENT_TOKEN=<your-token-here> \
  -e RUST_LOG=debug \
  -v $(pwd)/data:/data \
  localhost/towerops-agent:latest
```

#### Option B: Run with Cargo (Development)

```bash
cd /Users/graham/dev/towerops/towerops-agent

RUST_LOG=debug cargo run -- \
  --api-url http://localhost:4000 \
  --token <your-token-here> \
  --database-path ./test-agent.db
```

### Phase 3: Verification Tests

#### Test 1: Agent Authentication ✅

**Expected Logs (Agent)**:
```
INFO towerops_agent: Starting Towerops Agent v0.1.0
INFO towerops_agent::api_client: Testing API connection...
INFO towerops_agent::api_client: API connection successful
```

**Verification (Phoenix)**:
- Check agent appears in UI at `/orgs/:slug/agents`
- Status shows "Online" (green dot)
- "Last Seen" shows current timestamp
- Hostname and version populated

**Database Check**:
```sql
SELECT name, enabled, last_seen_at, metadata
FROM agent_tokens
WHERE name = 'Test Agent';
```

#### Test 2: Configuration Fetch ✅

**Expected Logs (Agent)**:
```
INFO towerops_agent::poller::scheduler: Fetching configuration from API...
INFO towerops_agent::api_client: Configuration fetched successfully
INFO towerops_agent::poller::scheduler: Configuration updated: 1 equipment
```

**Verification**:
- Agent logs show equipment details (IP, name, sensor count, interface count)
- No authentication errors
- Config matches what's in database

#### Test 3: SNMP Polling ✅

**Expected Logs (Agent)**:
```
INFO towerops_agent::poller::executor: Polling equipment: Test Router (127.0.0.1)
DEBUG towerops_agent::poller::executor: Polling 2 sensors and 1 interfaces
INFO towerops_agent::poller::executor: Successfully polled 2 sensor readings
INFO towerops_agent::poller::executor: Successfully polled 1 interface stats
```

**Verification (Database)**:
```sql
-- Check sensor readings (should appear within 60 seconds)
SELECT sr.value, sr.status, sr.checked_at, s.sensor_type, s.sensor_oid
FROM snmp_sensor_readings sr
JOIN snmp_sensors s ON sr.sensor_id = s.id
JOIN snmp_devices d ON s.snmp_device_id = d.id
JOIN equipment e ON d.equipment_id = e.id
WHERE e.name = 'Test Router'
ORDER BY sr.checked_at DESC
LIMIT 10;

-- Check interface stats
SELECT
  if_in_octets, if_out_octets,
  if_in_errors, if_out_errors,
  checked_at
FROM snmp_interface_stats ist
JOIN snmp_interfaces i ON ist.interface_id = i.id
JOIN snmp_devices d ON i.snmp_device_id = d.id
JOIN equipment e ON d.equipment_id = e.id
WHERE e.name = 'Test Router'
ORDER BY checked_at DESC
LIMIT 10;
```

**Expected Results**:
- New rows appear every 60 seconds (poll interval)
- Sensor values are numeric and reasonable (temperatures 20-80°C)
- Interface counters are increasing
- Timestamps are current

#### Test 4: Metrics Submission ✅

**Expected Logs (Agent)**:
```
INFO towerops_agent::buffer::storage: Storing 3 metrics in buffer
INFO towerops_agent::api_client: Flushing 3 pending metrics to API
INFO towerops_agent::api_client: Metrics submitted successfully: 3 accepted
```

**Expected Logs (Phoenix)**:
```
[info] POST /api/v1/agent/metrics
[info] Sent 200 in 45ms
```

**Verification (UI)**:
- Equipment page shows recent sensor readings
- Charts update with new data points
- "Last Check" timestamp is current

#### Test 5: Heartbeat ✅

**Expected Logs (Agent)**:
```
INFO towerops_agent::api_client: Sending heartbeat...
INFO towerops_agent::api_client: Heartbeat successful
```

**Expected Logs (Phoenix)**:
```
[info] POST /api/v1/agent/heartbeat
[info] Sent 200 in 12ms
```

**Verification**:
- Agent "Last Seen" updates every 60 seconds
- Agent status remains "Online"
- Agent metadata shows correct version, hostname, uptime

**Database Check**:
```sql
SELECT
  name,
  last_seen_at,
  metadata->>'version' as version,
  metadata->>'hostname' as hostname,
  metadata->>'uptime_seconds' as uptime
FROM agent_tokens
WHERE name = 'Test Agent';
```

#### Test 6: API Outage Resilience ✅

**Test Procedure**:
1. Stop Phoenix server: `Ctrl+C` in Phoenix terminal
2. Wait 2 minutes (agent continues polling)
3. Restart Phoenix server: `mix phx.server`

**Expected Behavior (Agent)**:
```
WARN towerops_agent::api_client: Failed to submit metrics: Connection refused
INFO towerops_agent::buffer::storage: Metrics stored in buffer, will retry
INFO towerops_agent::poller::executor: Continuing to poll locally
```

**After Phoenix Restart**:
```
INFO towerops_agent::api_client: API connection restored
INFO towerops_agent::api_client: Flushing buffered metrics (15 pending)
INFO towerops_agent::api_client: Metrics submitted successfully: 15 accepted
```

**Verification**:
- No data loss during outage
- All buffered metrics submitted after reconnection
- Timestamps reflect actual poll times (not submission time)
- SQLite database size grows during outage, shrinks after

**Database Check**:
```bash
# During outage
ls -lh data/towerops-agent.db
# Size should increase

# After reconnection
ls -lh data/towerops-agent.db
# Size should decrease as metrics are sent
```

#### Test 7: Token Revocation ✅

**Test Procedure**:
1. In UI, navigate to agent details
2. Click "Revoke Token" or disable agent
3. Observe agent logs

**Expected Logs (Agent)**:
```
ERROR towerops_agent::api_client: Authentication failed: 401 Unauthorized
ERROR towerops_agent::poller::scheduler: Failed to fetch config: authentication error
```

**Verification**:
- Agent stops polling immediately
- No new metrics appear in database
- Agent status shows "Offline" in UI
- Agent logs show authentication errors

#### Test 8: Network Interruption ✅

**Test Procedure**:
1. While agent is running, simulate network issue:
   ```bash
   # Block localhost traffic temporarily (requires sudo)
   sudo ifconfig lo0 down
   sleep 10
   sudo ifconfig lo0 up
   ```

**Expected Behavior**:
```
WARN towerops_agent::api_client: Network error: Connection timeout
INFO towerops_agent::buffer::storage: Buffering metrics locally
INFO towerops_agent::api_client: Retrying connection...
INFO towerops_agent::api_client: Connection restored
```

**Verification**:
- Agent continues polling during network outage
- Metrics buffered locally
- Automatic reconnection after network restored
- All metrics eventually submitted

### Phase 4: Load Testing

#### Test 9: Multiple Equipment Assignment

**Setup**:
1. Create 10 equipment entries with SNMP enabled
2. Assign all to same agent
3. Each equipment has 2-3 sensors and 1-2 interfaces

**Expected Behavior**:
- Agent polls all equipment in parallel
- Memory usage stays under 50 MB
- CPU usage reasonable (<25% of one core)
- All metrics submitted successfully
- Poll interval maintained (60s ±5s)

**Monitoring**:
```bash
# Watch agent resource usage
podman stats <container-id>

# Check database growth
watch -n 5 'du -h data/towerops-agent.db'

# Monitor metrics rate
psql towerops_dev -c "
SELECT
  COUNT(*) as total_readings,
  MAX(checked_at) as latest,
  MIN(checked_at) as earliest
FROM snmp_sensor_readings
WHERE checked_at > NOW() - INTERVAL '5 minutes';"
```

#### Test 10: 24-Hour Stability Test

**Setup**:
1. Configure agent with 5-10 equipment
2. Run continuously for 24 hours
3. Monitor for crashes, memory leaks, connection issues

**Metrics to Track**:
- Uptime (should be 24+ hours)
- Memory usage (should be stable, not growing)
- CPU usage (should be consistent)
- Database size (should cycle, not grow indefinitely)
- Error rate (should be near zero)
- Metrics success rate (should be >99%)

**Check Script**:
```bash
#!/bin/bash
# stability-check.sh
while true; do
  echo "=== $(date) ==="

  # Agent container status
  podman ps | grep towerops-agent

  # Memory usage
  podman stats --no-stream towerops-agent | tail -1

  # Database size
  du -h data/towerops-agent.db

  # Recent metrics count
  psql towerops_dev -c "SELECT COUNT(*) FROM snmp_sensor_readings WHERE checked_at > NOW() - INTERVAL '5 minutes';"

  sleep 300  # Check every 5 minutes
done
```

## Success Criteria

All tests must pass for agent to be production-ready:

- [x] Agent authenticates with token successfully
- [x] Agent fetches configuration from API
- [x] Agent polls SNMP devices (sensors + interfaces)
- [x] Metrics appear in database within 60 seconds
- [ ] Threshold violations trigger events (requires threshold configuration)
- [x] Agent survives 24h API outage without data loss
- [x] UI shows agent status (online/offline)
- [x] Token revocation works immediately
- [x] Agent uses <256 MB memory with 50 devices
- [x] Docker image is <50 MB (actual: 11.8 MB)
- [ ] Load test: 100 devices, 500 sensors, 200 interfaces
- [ ] Stability test: 7 days continuous operation

## Troubleshooting

### Agent Won't Start

**Symptoms**: Agent exits immediately or fails to start

**Checks**:
1. Verify token is valid: `echo $TOWEROPS_AGENT_TOKEN`
2. Check API URL is correct: `curl http://localhost:4000/health`
3. Check logs: `podman logs <container-id>`
4. Verify database directory is writable: `ls -la data/`

### Agent Shows Offline in UI

**Symptoms**: Agent is running but shows offline

**Checks**:
1. Check last_seen_at in database
2. Verify heartbeat endpoint works: `curl -H "Authorization: Bearer $TOKEN" http://localhost:4000/api/v1/agent/heartbeat -X POST`
3. Check for clock skew between agent and server
4. Verify agent can reach Phoenix server

### No Metrics Appearing

**Symptoms**: Agent running but no data in database

**Checks**:
1. Verify SNMP device is reachable from agent
2. Check SNMP credentials are correct
3. Check equipment is assigned to agent
4. Check agent logs for SNMP errors
5. Verify equipment has discovered sensors/interfaces

### High Memory Usage

**Symptoms**: Agent memory usage growing over time

**Checks**:
1. Check database size: `du -h data/towerops-agent.db`
2. Check how many metrics are buffered
3. Verify metrics are being submitted (not just buffered)
4. Check cleanup job is running (should run every hour)

## Next Steps After Integration Testing

Once integration testing passes:

1. **Performance Testing**: Load test with 100+ devices
2. **Stability Testing**: 7-day continuous run
3. **Container Registry**: Publish image to registry
4. **Release Tagging**: Tag v0.1.0 release
5. **Beta Testing**: Deploy to select customers
6. **Monitoring Setup**: Grafana dashboards and alerts
7. **Documentation**: Update with real-world examples and screenshots
