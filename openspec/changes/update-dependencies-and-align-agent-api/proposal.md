# Proposal

## Why

The agent's dependency versions span Go modules, the compiler, container images, CI actions and Nix tooling; updating only `go.mod` leaves part of the shipped supply chain untouched. Dependency upgrades must preserve the actual agent API contract in the sibling `towerops-web` repository, including its hand-written protobuf codecs and Phoenix channel behavior, not merely matching `.proto` files.

## What Changes

- Resolve every agent dependency surface to its latest stable release at implementation time, including major versions; migrate affected callers rather than retaining compatibility shims. Record already-current dependencies rather than manufacturing changes.
- Align Go requirements, the Docker builder and Nix development tooling; refresh Nix lock inputs, protobuf generation tooling and CI action/tool pins together where coupled.
- Preserve the existing rolling Wolfi runtime policy, rebuilding with fresh upstream packages and applying the existing image vulnerability gate.
- Compare both protobuf schemas, generated Go bindings, server codecs, channel events, authentication, heartbeat capabilities, recurring inventories and result ingestion. Correct confirmed drift on the owning side and add cross-language behavioral coverage where the current coverage cannot detect it.
- Fix the three demonstrated alignment gaps: missing release-webhook HMAC authentication, SNMP frames that can exceed the server's OID-entry count cap, and credential-probe int32 codec edge semantics.
- Exercise the upgraded binary against the real Towerops agent endpoint before release; document supported versions and coordinated rollout requirements if the contract changes.

## Capabilities

### New Capabilities

These are the agent repository's first OpenSpec contracts, capturing existing behavior that upgrades must preserve as well as the dependency currency requirement:

- `release-compatibility`: stable dependency currency and reproducible evidence for the compiler, development environment and released container.
- `agent-api`: interoperable agent/server wire messages, capability negotiation, scheduling and result delivery across the authenticated agent channel.

### Modified Capabilities

None; this repository has no existing OpenSpec capability specifications.

## Impact

- Agent: `go.mod`, `go.sum`, `Dockerfile`, `flake.nix`, `flake.lock`, `.github/workflows/ci.yml`, protobuf generation and any callers affected by actual dependency API changes.
- Agent contract: `proto/agent.proto`, `pb/agent.pb.go`, `agent.go`, `websocket.go`, relevant executors and existing contract tests, only where the audit demonstrates a necessary change.
- Towerops counterpart: `../towerops-web/priv/proto/agent.proto`, `lib/towerops/proto/`, `lib/towerops_web/channels/agent_channel*`, socket configuration and targeted tests if alignment requires server changes.
- Documentation: `README.md` and `CONTRIBUTING.md` for toolchain, contract ownership, supported versions and verification commands.
- Non-goals: upgrading unrelated Towerops web application, frontend or Terraform-provider dependencies; replacing the WebSocket API with REST; adding new monitoring features, protocol redesigns or generic retry/telemetry mechanisms.
- Implementation updates both working trees. Server codec/reassembly corrections must ship first; this apply does not publish releases or deploy production services. Exercised verification is recorded in `design.md`.
