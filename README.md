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

- **SNMP polling** — GET and WALK against SNMPv1, v2c and v3 devices
- **SNMP discovery** — walks a device to enumerate sensors, interfaces and neighbours
- **SNMP credential testing** — validates a credential set against a device before you save it
- **ICMP monitoring** — reachability and round-trip time
- **MikroTik RouterOS** — polling over the binary API, and configuration backup over the API or SSH `/export`
- **LLDP topology** — LLDP-MIB walks that feed link discovery
- **Service checks** — HTTP(S), TCP, DNS and TLS-certificate-expiry checks

It also accepts unsolicited input, when enabled:

- **SNMP trap receiver** — SNMPv1 and v2c traps and informs on UDP 162,
  forwarded to Towerops and attached to the device that sent them

Operational properties:

- **Outbound only** — one WebSocket over TLS, authenticated with an agent token; no inbound connections unless the trap listener is enabled
- **Server driven** — assignment, schedule and credential changes take effect without restarting the agent
- **Automatic reconnection** — exponential backoff with jitter, 1s to 10s
- **Server-triggered update and restart** — see [Updating](#updating)
- **Trust on first use** — SSH host keys and MikroTik TLS certificates are pinned on first contact
- **Trap forwarding survives reconnects** — the trap listener runs independently
  of the WebSocket session and queues up to 1000 traps while the agent is
  reconnecting

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

Every setting has an environment variable and an equivalent flag; the flag
wins.

| Variable | Flag | Description | Default |
|----------|------|-------------|---------|
| `TOWEROPS_API_URL` | `--api-url` | Towerops base URL, e.g. `https://towerops.net`. `http`/`https` is rewritten to `ws`/`wss`; a bare host is assumed `wss`. | Required |
| `TOWEROPS_AGENT_TOKEN` | `--token` | Agent authentication token | Required |
| `LOG_LEVEL` | `--log-level` | `error`, `warn`, `info` or `debug` | `info` |
| `LOG_FORMAT` | `--log-format` | `text` for human-readable lines, coloured only on a terminal, or `json` for structured records | `text` |
| `TOWEROPS_HOST_KEYS_FILE` | — | Path to the trust-on-first-use store for SSH host keys and MikroTik TLS fingerprints. Must be writable, or SSH and TLS connections are refused. | `./known_hosts.json` for a local binary; `/data/known_hosts.json` in the published image |
| `TRAP_ENABLED` | `--trap-enabled` | Listen for SNMP traps | `false` |
| `TRAP_PORT` | `--trap-port` | UDP port for the trap listener | `162` |
| `TRAP_COMMUNITY` | `--trap-community` | Only accept traps carrying this community string. Unset accepts any community. | unset |

Two flags have no environment variable:

- `--token-file <path>` — read the token from a file instead of the
  environment. Preferred over `--token`, which is visible in the process
  table and warns on startup.
- `--insecure` — permit a plaintext `ws://` connection. Refused otherwise.

## Architecture

```
Towerops server ──WebSocket/TLS──▶ agent ──▶ SNMP / ICMP / SSH / RouterOS API / HTTP
```

1. The agent connects to `{TOWEROPS_API_URL}/socket/agent/websocket` and joins
   the `agent:<id>` channel with its token. A rejected token ends the session.
2. The server immediately pushes the agent's job list, and pushes it again
   whenever assignments, credentials or checks change.
3. Jobs are executed on bounded worker pools — one per protocol — so a slow
   or unreachable device cannot stall the rest.
4. Results are streamed back as they complete. SNMP results are batched for up
   to 100ms to keep message volume down.
5. The agent sends a heartbeat every 60s carrying its version, uptime and
   architecture, plus a channel keepalive every 25s. The server drops an agent
   that goes 5 minutes without a heartbeat.
6. On any disconnect the agent reconnects with exponential backoff (1s to 10s,
   plus up to 25% jitter). A session that lasts 30s resets the backoff.

Messages are Protocol Buffers ([`proto/agent.proto`](proto/agent.proto))
carried inside the Phoenix channel envelope.

## SNMP trap listener

Set `TRAP_ENABLED=true` to listen for traps, and point your devices at the
agent's address on UDP 162. The agent parses SNMPv1 and SNMPv2c traps and
informs, normalises them, and forwards each one to Towerops, which attaches it
to the device whose management IP matches the trap's source address.

SNMPv1 header fields are mapped to a v2c-style trap OID following RFC 3584
§3.1, so a trap has one identifier regardless of the version that delivered it.

Traps are unauthenticated by design: anything that can reach the port can send
one. Set `TRAP_COMMUNITY` to reject traps that do not carry the expected
community string, and firewall the port to your device network. Each trap is
capped at 128 variable bindings, and the agent queues at most 1000 traps while
it has no server connection — beyond that further traps are dropped and the
count is logged.

In Docker, publish the port. The image already grants the binary
`cap_net_bind_service`, so binding the privileged port 162 as a non-root user
needs no extra Docker capability:

```yaml
    ports:
      - "162:162/udp"
    environment:
      - TRAP_ENABLED=true
```

## Updating

Container deployments update by pulling a new image. Watchtower is the
supported way to automate that, and the Compose file Towerops generates
includes it.

The server can also push an update to a standalone binary: it sends a download
URL and a SHA-256 digest, and the agent fetches the binary over HTTPS, verifies
the digest before and after writing it, replaces itself atomically, and
re-executes. This needs write access to the *directory* holding the binary, so
it does not apply to the published image, where `/usr/local/bin` is root-owned
and the process runs unprivileged. Note that a replaced binary loses any file
capabilities granted with `setcap`.

The server can also ask an agent to restart, which drops the session and
reconnects immediately.

## Building from source

Requires Go 1.27 or later. A Nix dev shell with the pinned toolchain, linter
and protobuf compiler is included — see [CONTRIBUTING.md](CONTRIBUTING.md).

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
connected on the Agents page. Run with `LOG_LEVEL=debug` to see per-job detail.

**SSH or MikroTik TLS connections refused.** The host key or certificate
changed since it was pinned, or the store is not writable. In the published
image, check that `/data` is mounted persistently and that
`TOWEROPS_HOST_KEYS_FILE` is `/data/known_hosts.json`.

**ICMP checks failing.** Standard Docker already grants `NET_RAW`, and the
image binary carries `cap_net_raw+ep`. Under a hardened runtime that drops the
capability, grant `NET_RAW` if its policy permits; otherwise the agent tries
unprivileged UDP ping and `ping(8)` after raw sockets fail.

**Traps not arriving.** Confirm `TRAP_ENABLED=true` and that UDP 162 is
published and not blocked. Run with `LOG_LEVEL=debug`: every accepted trap is
logged with its source and trap OID, and a community mismatch is logged as
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
  `TRAP_COMMUNITY` to filter on the community string.
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

**One exception:** `proto/agent.proto` and the Go bindings generated from it
in `pb/` are licensed **Apache-2.0** ([LICENSE.Apache-2.0](LICENSE.Apache-2.0)).
That file is the wire contract between the agent and the server rather than
part of the agent itself, so anyone can implement this protocol — in any
language, under any license — without taking on copyleft obligations.
Speaking the protocol is not what makes something a derivative work.

Contributions are accepted under the Developer Certificate of Origin; see
[CONTRIBUTING.md](CONTRIBUTING.md).
