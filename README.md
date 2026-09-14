# Towerops Agent

A remote polling agent for Towerops network monitoring.

## Overview

The agent runs inside your network and does the polling that Towerops cannot
do from the outside. It holds no configuration of its own: it opens a single
outbound WebSocket to the Towerops server, and the server dispatches every
job over that connection. Nothing needs to be reachable from the internet
except the optional SNMP trap listener.

## What it does

Jobs the server can dispatch:

- **SNMP polling** - GET and WALK against SNMPv1, v2c and v3 devices
- **SNMP discovery** - walks a device to enumerate sensors, interfaces and neighbours
- **SNMP credential testing** - validates a credential set against a device before you save it
- **ICMP monitoring** - reachability and round-trip time
- **MikroTik RouterOS** - polling over the binary API, and configuration backup over the API or SSH `/export`
- **LLDP topology** - LLDP-MIB walks that feed link discovery
- **Service checks** - HTTP(S), TCP, DNS and TLS-certificate-expiry checks

It also accepts unsolicited input, when enabled:

- **SNMP trap receiver** - SNMPv1 and v2c traps and informs on UDP 162,
  forwarded to Towerops and attached to the device that sent them

Operational properties:

- **Outbound only** - one WebSocket over TLS, authenticated with an agent token; no inbound connections unless the trap listener is enabled
- **Server driven** - assignment, schedule and credential changes take effect without restarting the agent
- **Automatic reconnection** - exponential backoff with jitter, 1s to 10s
- **Server-triggered update and restart** - see [Updating](#updating)
- **Trust on first use** - SSH host keys and MikroTik TLS certificates are pinned on first contact
- **Trap forwarding survives reconnects** - the trap listener runs independently
  of the WebSocket session and queues up to 1000 traps while the agent is
  reconnecting
- **Reconnect result buffering** - up to 512 completed job results remain in
  memory across temporary WebSocket disconnects and are retried after reconnect

## Quick start

Create an agent token in Towerops under **Organization → Agents → Create New
Agent**, then run:

```bash
docker run -d --name towerops-agent --restart unless-stopped \
  -v towerops-agent-data:/data \
  --cap-add NET_RAW \
  -e TOWEROPS_API_URL=https://towerops.net \
  -e TOWEROPS_AGENT_TOKEN=your-agent-token \
  ghcr.io/towerops-app/towerops-agent:latest
```

Docker includes `NET_RAW` by default, and the image binary carries
`cap_net_raw+ep`. The explicit `--cap-add NET_RAW` only matters under runtimes
that drop it, such as Kubernetes restricted PSS or some hardened Docker
daemons. Without raw sockets the agent falls back to unprivileged UDP ping and
then to the system `ping` binary.

The published image stores its trust-on-first-use data at
`/data/known_hosts.json` and declares `/data` as a volume. Keep `/data` on a
named volume or bind mount, as in the example, so SSH host keys and MikroTik TLS
fingerprints remain pinned when the container is recreated.

For Compose, see [docker-compose.example.yml](docker-compose.example.yml).
The Agents page in Towerops also generates a ready-to-paste Compose file with
your API URL and token filled in.

## Configuration

Flags override their corresponding environment variables.

| Variable | Flag | Description | Default |
|----------|------|-------------|---------|
| `TOWEROPS_API_URL` | `--api-url` | Towerops base URL, e.g. `https://towerops.net`. `http`/`https` is rewritten to `ws`/`wss`; a bare host is assumed `wss`. | Required |
| `TOWEROPS_AGENT_TOKEN` | `--token` | Agent authentication token | Required |
| `TOWEROPS_LOG_LEVEL` | `--log-level` | `error`, `warn`, `info` or `debug` | `info` |
| `TOWEROPS_LOG_FORMAT` | `--log-format` | `text` for human-readable lines, coloured only on a terminal, or `json` for structured records | `text` |
| `TOWEROPS_INSECURE` | `--insecure` | Permit a plaintext `ws://` connection. Refused otherwise. | `false` |
| `TOWEROPS_HOST_KEYS_FILE` | `--host-keys-file` | Path to the trust-on-first-use store for SSH host keys and MikroTik TLS fingerprints. The path is checked for writability at startup. | `./known_hosts.json` for a local binary; `/data/known_hosts.json` in the published image |
| `TOWEROPS_TRAP_ENABLED` | `--trap-enabled` | Listen for SNMP traps | `false` |
| `TOWEROPS_TRAP_BIND` | `--trap-bind` | Local address for the trap listener. Use `::` to receive traps from IPv6-only devices. | `0.0.0.0` |
| `TOWEROPS_TRAP_PORT` | `--trap-port` | UDP port for the trap listener | `162` |
| `TOWEROPS_TRAP_COMMUNITY` | `--trap-community` | Only accept traps carrying this community string. Unset accepts any community. | unset |
| `TOWEROPS_LEGACY_SCHEDULING` | `--legacy-scheduling` | Disable local recurring scheduling and advertise `schedules_jobs: false`, restoring server-driven refreshes during a rollback. | `false` |

The legacy unprefixed variables `LOG_LEVEL`, `LOG_FORMAT`, `TRAP_ENABLED`,
`TRAP_PORT` and `TRAP_COMMUNITY` remain accepted when the corresponding
`TOWEROPS_` variable is unset.

`--token-file <path>` has no environment variable. It reads the token from a
file instead of the environment and is preferred over `--token`, which is
visible in the process table and warns on startup.

## Architecture

```
Towerops server ──WebSocket/TLS──▶ agent ──▶ SNMP / ICMP / SSH / RouterOS API / HTTP
```

1. The agent connects to `{TOWEROPS_API_URL}/socket/agent/websocket` and joins
   the `agent:<id>` channel with its token. A rejected token ends the session.
2. The server pushes the connection's complete recurring `jobs` and
   `check_jobs` inventories on join, then pushes replacements whenever
   assignments, credentials, or intervals change. Ad-hoc work uses the
   backwards-compatible `discovery_job` or `backup_job` one-shot lanes.
3. Newly assigned recurring work runs promptly, then at its configured
   interval. `AgentJob.interval_seconds = 0` identifies one-shot work. One
   stable assignment ID never overlaps itself; a changed assignment waits for
   its active predecessor to stop, and superseded waiters exit immediately.
4. Jobs execute on bounded worker pools - one per protocol - so a slow or
   unreachable device cannot stall the rest. Recurring schedulers wait for
   bounded queue capacity instead of dropping synchronized ticks. Interactive
   overload remains visible to the server as an `AgentError`.
5. Results are streamed back as they complete. A cancelled job produces no
   measurement. Completed results and traps use a bounded process-wide spool
   across reconnects; a successful socket write removes an item, so delivery is
   at-most-once rather than server-acknowledged. The server batches ICMP result
   persistence for up to 100ms; the agent does not batch SNMP results on the wire.
6. The agent sends a heartbeat every 60s carrying its version, process uptime
   and architecture, plus a channel keepalive every 25s. Version 1.5.0 and
   later advertise `schedules_jobs` unless `--legacy-scheduling` is set. The
   server drops an agent that goes 5 minutes without a heartbeat.
7. On any disconnect the scheduler is cancelled and its credential-bearing
   inventory is discarded before reconnect. The new authenticated connection
   must provide complete lists again; assignments are never persisted locally.
8. Reconnection uses exponential backoff (1s to 10s, plus up to 25% jitter). A
   session that lasts 30s resets the backoff.

### Scheduler rollout compatibility

Deploy the server first. Retire its legacy 60-second list re-push only when both
sides meet these minimum versions:

| Component | Minimum version | Required wire behavior |
|-----------|-----------------|------------------------|
| Towerops server | 0.2.0 | Populates each recurring `AgentJob.interval_seconds` and pushes complete, including empty, job and check lists after assignment changes. |
| Towerops agent | 1.5.0 | Retains recurring lists, schedules jobs and checks locally, and advertises `AgentHeartbeat.schedules_jobs`. |

Server 0.1.x does not populate per-job intervals or push an empty list after the
last assignment is removed. Use `--legacy-scheduling` only as a rollback escape
hatch with such a server: the agent advertises `schedules_jobs: false` and runs
each refreshed list once instead of retaining it. Repeated unchanged lists in
local scheduling mode do not reset timers or trigger an extra run.

Messages are Protocol Buffers ([`proto/agent.proto`](proto/agent.proto))
carried inside the Phoenix channel envelope.

### Resilience details

- SNMPv1 `noSuchName` and `tooBig` responses recursively halve a GET batch,
  recovering every individually valid OID instead of discarding the whole
  response.
- ICMP tries a raw socket, then an unprivileged UDP socket, then `ping(8)`.
- Standalone self-updates compare SHA-256 digests in constant time, atomically
  replace the binary, and re-exec the process. Container deployments refuse
  self-update because their binary comes from the image.

## SNMP trap listener

Set `TOWEROPS_TRAP_ENABLED=true` to listen for traps, and point your devices at
the agent's address on UDP 162. The listener binds `0.0.0.0` by default; set
`TOWEROPS_TRAP_BIND=::` to receive traps from IPv6-only devices. The agent parses
SNMPv1 and SNMPv2c traps and informs, normalises them, and forwards each one to
Towerops, which attaches it to the device whose management IP matches the
trap's source address. SNMPv3 traps are not supported because the listener has
no configured USM user or authentication material.

SNMPv3 traps and informs are not supported. The listener has no USM user,
authentication, or privacy configuration, so it cannot decode SNMPv3 messages.
Configure devices to send SNMPv1 or SNMPv2c notifications to this listener, or
use a separate receiver that supports SNMPv3.

SNMPv1 header fields are mapped to a v2c-style trap OID following RFC 3584
§3.1, so a trap has one identifier regardless of the version that delivered it.

Traps are unauthenticated by design: anything that can reach the port can send
one. Set `TOWEROPS_TRAP_COMMUNITY` to reject traps that do not carry the
expected community string, and firewall the port to your device network. Each
trap is capped at 128 variable bindings, and the agent queues at most 1000
traps while it has no server connection - beyond that further traps are
dropped and the count is logged.

In Docker, publish the port. The image already grants the binary
`cap_net_bind_service`, so binding the privileged port 162 as a non-root user
needs no extra Docker capability:

```yaml
    ports:
      - "162:162/udp"
    environment:
      - TOWEROPS_TRAP_ENABLED=true
```

## Updating

Container deployments update by pulling a new image. Watchtower is the
supported way to automate that, and the Compose file Towerops generates
includes it. A containerised agent reports `container: true` in its heartbeat
so the server can avoid sending binary updates. If one is sent, the agent
refuses it with a clear `self-update unsupported in this deployment` error.

The server can push an update to a standalone binary: it sends a download URL
and a SHA-256 digest, and the agent fetches the binary over HTTPS, verifies the
digest before and after writing it, replaces itself atomically, and re-executes.
This needs write access to the directory holding the binary. Replacing a binary
that was granted file capabilities with `setcap` removes those capabilities;
the agent logs a warning when it replaces itself so the loss is visible.

The server can also ask an agent to restart, which drops the session and
reconnects immediately.

## Building from source

Requires Go 1.27 or later. A Nix dev shell with the pinned toolchain, linter
and protobuf compiler is included - see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
make build          # or: go build -o towerops-agent .
docker build -t towerops-agent .
```

## Troubleshooting

**Agent not connecting.** Check `TOWEROPS_API_URL` is reachable from the
container and that the token has not been revoked or disabled:
`docker logs towerops-agent`. A join failure is logged as `join rejected`.

**No metrics appearing.** Confirm equipment is assigned to this agent in
Towerops, that its SNMP credentials are correct, and that the agent shows as
connected on the Agents page. Run with `TOWEROPS_LOG_LEVEL=debug` to see
per-job detail.

**Host key store error at startup.** Check that the
`TOWEROPS_HOST_KEYS_FILE` path is readable and its directory is writable. In
the published image, `/data` must be mounted persistently and the path should
be `/data/known_hosts.json`.

**SSH or MikroTik TLS connections refused.** The host key or certificate
changed since it was pinned.

**ICMP checks failing.** Standard Docker already grants `NET_RAW`, and the
image binary carries `cap_net_raw+ep`. Under a hardened runtime that drops the
capability, grant `NET_RAW` if its policy permits; otherwise the agent tries
unprivileged UDP ping and `ping(8)` after raw sockets fail.

**Traps not arriving.** Confirm `TOWEROPS_TRAP_ENABLED=true` and that UDP 162 is
published and not blocked. Run with `TOWEROPS_LOG_LEVEL=debug`: every accepted
trap is logged with its source and trap OID. A community mismatch is logged as
`dropping trap with unexpected community`. Towerops can only attach a trap to a
device whose management IP equals the trap's source address; traps from unknown
addresses are still recorded against the organization.

## Security

- The agent token is a credential; treat it like a password and prefer
  `--token-file` or the environment over `--token`.
- The control channel uses TLS with certificate verification. `ws://` requires
  `--insecure`.
- The only listening socket is the optional trap listener. Traps are
  unauthenticated: restrict UDP 162 to your device network and set
  `TOWEROPS_TRAP_COMMUNITY` to filter on the community string.
- SNMP community strings and SSH credentials are never logged.
- Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 Graham McIntire

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details.

Contributions are accepted under the Developer Certificate of Origin; see
[CONTRIBUTING.md](CONTRIBUTING.md).
