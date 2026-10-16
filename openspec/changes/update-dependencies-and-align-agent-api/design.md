# Design

## Context

See `proposal.md` for scope. Implementation evidence and deviations from the initial dependency snapshot are recorded below; `tasks.md` tracks exercised acceptance criteria.

The API has two relevant surfaces: the Phoenix agent channel and the HTTP release notification sent by CI. The canonical wire schema lives in `../towerops-web/priv/proto/agent.proto`; Go mirrors it and uses generated bindings, while the server maintains its codecs by hand. The existing server synchronization script was executed successfully during planning: `Agent protocol body matches canonical priv/proto/agent.proto`. This proves schema-body equality, not codec interoperability.

The seven modules declared in `go.mod` already match their observed latest stable releases. A complete `go list -mod=readonly -m -u -json all` run additionally found an outdated graph-only legacy protobuf requirement; `go mod graph` traces it to the modern protobuf module. The graph entry is not evidence that legacy protobuf is linked into the agent binary.

### Dependency resolution evidence

Observed on 2026-10-16; re-resolve before implementation.

| Surface | Current | Observed target / decision |
|---|---|---|
| Go minimum / selected compiler | module 1.27.0; installed and locked Nix compiler 1.27.1 | [1.27.2](https://go.dev/dl/?mode=json); raise the patch minimum and align supported builds |
| Declared modules | websocket 1.8.15; gosnmp 1.45.0; x/crypto 0.58.0; x/net 0.61.0; protobuf 1.36.12; rapid 1.3.0; x/sys 0.49.0 | Already current; retain unless re-resolution changes the targets |
| Graph-only legacy protobuf | github.com/golang/protobuf 1.5.0, required by google.golang.org/protobuf | [1.5.4](https://proxy.golang.org/github.com/golang/protobuf/@latest); reconcile the selected indirect graph without replacing the modern protobuf API or claiming the legacy package ships |
| Other selected graph modules | mock 1.6.0; go-cmp 0.7.0; testify 1.12.1; yaml/v3 3.0.5; x/term 0.47.0; x/text 0.43.0 | No newer same-path versions reported by the complete module query |
| CI and Nix golangci-lint | 2.13.2 | [2.15.0](https://github.com/golangci/golangci-lint/releases/tag/v2.15.0); newest observed nixpkgs supplies only 2.14.0 |
| Nix protobuf compiler | locked package 35.1; committed binding header reports protoc 7.36.2 | [36.2](https://github.com/protocolbuffers/protobuf/releases/tag/v36.2); reconcile shell/generation reproducibility |
| protoc-gen-go/runtime | 1.36.12 | [1.36.12](https://proxy.golang.org/google.golang.org/protobuf/@latest), already current |
| Nix Git | 2.55.0 | [2.56.0](https://api.github.com/repos/git/git/tags?per_page=5); observed newest nixpkgs still supplies 2.55.0 |
| Nix gopls | 0.23.0 | [0.24.0](https://proxy.golang.org/golang.org/x/tools/gopls/@latest); observed newest nixpkgs still supplies 0.23.0 |
| Nix Delve | 1.27.1 | [1.27.2](https://proxy.golang.org/github.com/go-delve/delve/@latest) |
| Docker builder | floating `golang:1.27-alpine3.24` | [Already resolves to Go 1.27.2 / Alpine 3.24](https://hub.docker.com/v2/repositories/library/golang/tags/1.27-alpine3.24); preserve rolling patch-tag policy, pull fresh |
| Wolfi runtime and APK packages | rolling `latest`, unversioned fresh packages | Preserve policy; actual manifest query returned HTTP 401, so record image digests/installed versions during authenticated build, not guessed targets |

Module registry sources follow `https://proxy.golang.org/<module>/@latest`; the complete selected-graph command also independently reported only the legacy protobuf update. Additional checksum entries are not a reason to hand-edit `go.sum`.

All eleven action references already track the latest observed release majors. Retain their existing moving-major policy, and verify the refs resolve correctly rather than converting them to exact tags just to create changes:

| Action | Current ref | Observed stable release |
|---|---|---|
| actions/checkout | v7 | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) |
| actions/setup-go | v7 | [v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0) |
| golangci/golangci-lint-action | v9 | [v9.3.0](https://github.com/golangci/golangci-lint-action/releases/tag/v9.3.0) |
| docker/setup-buildx-action | v4 | [v4.4.1](https://github.com/docker/setup-buildx-action/releases/tag/v4.4.1) |
| docker/login-action | v4 | [v4.6.0](https://github.com/docker/login-action/releases/tag/v4.6.0) |
| docker/build-push-action | v7 | [v7.4.0](https://github.com/docker/build-push-action/releases/tag/v7.4.0) |
| anchore/scan-action | v7 | [v7.4.2](https://github.com/anchore/scan-action/releases/tag/v7.4.2) |
| github/codeql-action/upload-sarif | v4 | [v4.39.0](https://github.com/github/codeql-action/releases/tag/v4.39.0) |
| actions/upload-artifact | v7 | [v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) |
| actions/download-artifact | v8 | [v8.0.2](https://github.com/actions/download-artifact/releases/tag/v8.0.2) |
| softprops/action-gh-release | v3 | [v3.0.3](https://github.com/softprops/action-gh-release/releases/tag/v3.0.3) |

Observed configured-branch input heads:

| Nix input | Locked revision | Observed upstream revision |
|---|---|---|
| nixpkgs-unstable | d5dfd8e6716dde34398bc14bc87c10dece9c8c68 | [95b2dd0e78e6642fa7fd8fe5bb673daf4cebb924](https://api.github.com/repos/NixOS/nixpkgs/commits/nixpkgs-unstable) |
| flake-utils | 11707dc2f618dd54ca8739b309ec4fc024de578b | [b7a79d3fea1e214f6d668d521cecec0c01e26544](https://api.github.com/repos/numtide/flake-utils/commits/main) |
| systems | da67096a3b9bf56a91d16901293e51ba5b49a27e | [d36eeed142f88b5a636f2e3856a53c61654cf29b](https://api.github.com/repos/nix-systems/default/commits/main) |

These are branch snapshots, not stable semantic releases. A lock refresh alone does not satisfy latest-tool targets: if re-resolution still finds the packaging lag above, add narrowly scoped Nix package overrides for the stable linter, gopls and Git releases, using real fetched source/vendor hashes. Do not downgrade CI to the lagging Nix linter or introduce an alternate manual installation workflow.

## Goals / Non-Goals

**Goals:** Resolve every agent dependency surface, migrate necessary APIs, preserve supported behavior, fix demonstrated cross-repository drift, and leave a reproducible verification record.

**Non-goals:** A broad web dependency upgrade, new agent operations, replacing hand-written Elixir codecs, changing deployment security policy, retiring historical protocol fields just because current producers no longer use them, or introducing general-purpose compatibility infrastructure.

## Decisions

### 1. Resolve stable releases as one upgrade set

Resolve modules, compiler, image tags, CI integrations and Nix inputs at implementation time; record resolution time and sources. Include new major releases and their migration requirements, exclude prereleases, and distinguish latest available from latest compatible. Use `go list -m -u -json all` plus upstream release/module-path checks because the Go command does not discover a new `/vN` module path automatically. Apply explicit module targets, then tidy once after caller migrations. Do not blindly use `go get -u ./...` as the entire upgrade strategy.

Refresh `flake.lock` from the declared upstream branches, including transitive inputs. Evaluate the resulting packages, not just the lockfile revision: Go, golangci-lint, protoc-gen-go, protoc, gopls and delve must support the selected compiler and generation workflow. Keep CI's separately pinned linter compatible with that compiler. Resolve the current Go patch for local, CI and container builds; explain any difference between a language minimum and an actual compiler version rather than pretending the `go` directive pins every build.

Retain the current rolling-image policy. Rebuild with fresh builder/runtime pulls and refreshed Wolfi packages; record resolved platform digests/package versions as release evidence instead of silently changing the project to a digest-pinning policy. Check all action references, including release creation and SARIF upload, against current stable upstream releases and runtime/permission requirements.

### 2. Preserve canonical ownership; verify bytes in both languages

Edit server schema/codecs first only if a contract change is actually necessary, mirror the schema verbatim below the header, and regenerate Go exclusively with `make proto`. Never hand-edit `pb/agent.pb.go`. Do not change field numbers, enum identities or reserved values to accommodate dependency updates.

Add semantic interoperability fixtures in the existing Go/ExUnit test conventions: bytes emitted by the actual producer must be decoded by the peer and checked for intended values. Extend the existing Go-produced SNMP-trap fixture pattern rather than inventing another protocol framework. Cover server-produced jobs/checks/backup plans and agent-produced heartbeat, SNMP/MikroTik/check/backup/credential results where cross-language coverage is missing. Use default, negative and optional-field cases that can expose real codec differences; do not replace this with local round trips, source-text assertions or non-empty-byte checks.

### 3. Correct the release notification sender

Confirmed mismatch: `.github/workflows/ci.yml:323-337` sends only `Authorization: Bearer ...`, whereas `towerops-web/lib/towerops_web/controllers/api/v1/agent_release_webhook_controller.ex:87-117` requires `x-agent-webhook-signature` as well. The timestamp is Unix seconds; the digest is lowercase HMAC-SHA256 of `timestamp + "." + exact_raw_body` using the same webhook secret. The permitted clock difference is 300 seconds in either direction (`:148-165`). Missing signatures return 401. No live release request was sent during planning.

Generate the timestamp and digest in the existing CI notification step and send both credentials. Retain the existing empty HTTP body unless an actual payload is needed; sign exactly those empty bytes, not a newline or an invented JSON object. Use tooling available on the runner, keep the secret out of logs and command tracing, and verify the resulting request against the real server verifier with a disposable secret. Preserve the current missing-secret skip and notification failure policy; fixing authentication does not require redesigning release promotion or retries. Do not weaken the server verifier.

### 4. Enforce the SNMP receiver's entry-count boundary at the producer

Confirmed limit mismatch: `snmp.go:230-370` splits outgoing `SnmpResult` messages by encoded byte budget, but the server decoder caps `oid_values` at 50,000 entries (`towerops-web/lib/towerops/proto/decode.ex:25,1342-1348`). More than 50,000 short OID values can fit below the byte cap. This is a demonstrated producer/consumer constraint mismatch, not an observed production failure.

Extend the existing SNMP framing algorithm to flush before either the byte budget or the 50,000-entry bound would be exceeded. Keep the server's defensive bound. Preserve sequence/final flags, completed/truncated root metadata, discovery phase and lossless union of values across frames. Reuse the existing splitting state; avoid pre-encoding or copying the full map merely to count entries. Verify empty, exact-boundary, boundary-plus-one and multi-frame results, including the server's 64-frame and 64MiB aggregate safeguards. A result beyond total supported bounds must retain explicit partial/truncation semantics, not be mislabeled as complete.

Implementation clarification: count-based splitting can span a single root's bucket. The old server heuristic retained an arrived root even when another chunk was missing, which could incorrectly authorize reconciliation. The server now retains observations but clears all completion claims for gapped, stale, superseded or over-cap frame sets. Complete sets still union root claims. This deliberately favors retaining stored rows over deleting rows from incomplete evidence, without adding a schema field.

Directional byte limits are intentionally different: server accepts a 10MiB base64 field under a 12,000,000-byte frame cap; agent accepts 10MiB decoded protobuf under a 16MiB socket cap; normal SNMP output targets 8MiB base64. Document units and direction instead of equating the constants. The server's 7MiB backup request intentionally leaves encoding headroom; do not raise it to the agent's 16MiB zero-value default.

### 5. Reconcile int32 credential-probe semantics without changing normal probes

`CredentialProbeResult.matched_index` is schema `int32`, but server encode/decode uses int64 helpers (`decode.ex:586-588`, `encode.ex:254-265`). Normal index 0, valid positive indexes and canonical -1 currently interoperate. Correct the server codec to protobuf int32 semantics using the existing wire helpers, preserving canonical negative encoding, zero/default behavior and invalid-index rejection at the consumer. Cross-language cases must include 0, -1 and out-of-int32-range wire values so the fix is not just a helper rename.

### 6. Preserve aligned runtime contracts and make support claims precise

Keep the current object-shaped Phoenix envelope and base64 protobuf payloads, token-at-join authentication, immediate capability heartbeat and existing result event names. Verify authoritative empty inventories, unchanged schedule retention, non-overlap on replacement, independent one-shot dispatch and credential disposal on reconnect. Do not infer interoperability from the passing schema check.

Keep `update` as JSON `{url, checksum}` rather than protobuf. Preserve HTTPS-only URLs/redirects, bare 64-hex SHA-256 verification, amd64/arm64 release asset naming and container self-update refusal. Restart currently reconnects; it does not exit the process for Docker to restart it.

Fix inaccurate documentation: the current server does not periodically refresh jobs for legacy scheduling, and decoding `supports_config_backup` does not implement a legacy MikroTik fallback. Existing agent documentation establishes server 0.2.0 / agent 1.5.0 as local-scheduler minimums. Preserve explicitly documented historical rollback behavior where it still applies, but do not claim it works with a current server that removed the producer. Legacy credential-test messages are not an active current-server workflow; do not expand this change into reviving or removing them.

## Verification and release sequence

1. Record current→target dependency evidence; resolve any unavailable source explicitly. Refresh tooling and dependencies, migrate callers, regenerate bindings, and implement the three concrete alignment fixes above before running the final checks.
2. Run the agent's existing vet/lint/race-test/build gates once after integration, retaining CI's full root-package statement coverage and both release architectures. Run the existing server schema-sync command and targeted codec/channel/webhook tests after counterpart edits. Use existing behavior tests; add regressions only for demonstrated edge cases and cross-language semantics.
3. Smoke the actual updated Go binary against the configured sibling Phoenix application with a disposable agent token: accepted/rejected join; persisted immediate heartbeat; recurring SNMP/PING and HTTP check over two intervals; assignment/credential/interval replacement; final-assignment removal; discovery and credential probe; plan backup and structured failure; reconnect with fresh schedules. Confirm result ingestion/storage, not just successful sends.
4. Exercise >50,000 short OIDs end to end, verifying receiver-acceptable frames and complete value union. Exercise effective message-size boundaries, a negative probe index and legacy/default optional fields through both codecs.
5. Send the notification step's actual signed request to an isolated server instance with a disposable webhook secret; observe HTTP 200 and an enqueued release worker. Observe 401 for missing signature, changed body and expired timestamp without triggering production mass updates. Verify asset selection for both architectures and a disposable standalone update/checksum rejection; never update the developer's real executable.
6. Build fresh containers for both supported architectures, run the existing Grype severity gate, and smoke the native image as non-root with its trust-store volume and network capabilities. Document unavailable hardware/emulation or live-service prerequisites rather than marking those scenarios passed.
7. Publish server codec fixes first if needed, then the upgraded agent/CI changes. The planned changes retain the wire schema, so no new feature negotiation is expected. Roll back images/binaries as a pair if runtime regressions appear; do not roll back by disabling TLS, HMAC, checksums or the image gate. Update README/CONTRIBUTING with actual supported versions and evidence after the smoke succeeds.

## Risks / Trade-offs

- Upstream stable versions can advance after planning. The inventory is a dated observation; re-resolution is an implementation prerequisite, not a reason to invent future targets.
- Refreshing Nix can change more tools than Go modules do. A lockfile update alone does not prove generator/linter compatibility.
- Cross-language codec tests may need the sibling development environment and database; live smoke needs issued credentials and controlled targets. Missing access blocks those acceptance criteria, not the reachable implementation.
- The existing 64-frame/64MiB discovery buffer remains a total-result bound. Entry-aware framing must not turn excessive results into misleading authoritative completion.
- Historical peer compatibility is not the same as current-current alignment. Documentation corrections must distinguish the supported current pair from old rollback servers.

## Implementation evidence — 2026-10-16

### Resolved dependency and packaging decisions

- Re-resolved all original selected module paths and next-major candidates. The declared modules were already current; YAML v4 was release-candidate-only and excluded. `go mod tidy`, `go mod verify` and `go list -mod=readonly -m -u all` succeeded with no remaining update entries.
- The graph-only legacy protobuf dependency is not imported. A direct version bump was removed by tidy; instead of retaining an artificial import or replacement shim, `go.mod` excludes the obsolete v1.5.0 node. The modern protobuf API/runtime remains unchanged.
- Realized the updated Nix shell and observed executable versions matching the tool table in `CONTRIBUTING.md`. Regenerated bindings through `make proto`; no generated source was hand-edited.
- Git's stable-release override removes an already-upstreamed Darwin patch and quotes an upstream test redirect whose path contains spaces. The package's tests remain enabled. Source and vendor hashes were obtained from actual fetches.
- Existing action major refs and rolling builder/Wolfi policy remain intact. The builder currently resolves to the selected compiler patch; neither unchanged tags nor already-current modules are represented as version bumps.
- Current Towerops' application version is not a reliable wire-feature minimum: the exercised server identifies as application 0.1.0 while implementing the current scheduling contract. README compatibility now states required capabilities and server-first rollout rather than retaining the unsupported blanket 0.2.0 minimum claim.

### Agent quality gates

- `nix develop --command go vet ./...` passed. golangci-lint 2.15.0 reported zero issues after migrating three previously unchecked error-channel receives in existing tests to explicit cancellation/error handling.
- The CI-equivalent race/coverage run passed with 100.0% statement coverage. The exact zero-uncovered-root-statements guard also passed; the result is not based on rounded coverage alone.
- A static final binary built successfully with the selected toolchain and its actual `--help` output was exercised.
- `nix develop --command make test` passed for all packages. Before correction, its hardcoded 60-second suite deadline expired during normally progressing tests; the complete passing suite takes about 164 seconds here. The target now matches CI's Go-default suite timeout. No tests were skipped and individual scenario budgets were not loosened.

### Exercised server and live interoperability

- Canonical schema synchronization succeeded after the comment-only protocol documentation updates; wire field numbers, types and reserved values did not change.
- Server targeted suite: 509 checks passed with `TEST_POOL_SIZE=1` (505 tests and 4 properties). The initial concurrent run encountered a PostgreSQL DDL deadlock during fixture setup; serial isolation resolved that environmental conflict without changing application behavior.
- After replacing incidental internal-counter assertions and consolidating full-message semantic assertions, the 16 touched fixture/buffer tests passed and the sibling repository's changed-area `mix precommit` passed. The release-checker suites passed 11 additional checks.
- Actual Go-produced frames passed through the compiled Elixir decoder and reassembler: 50,001 readings survived as a lossless union; a missing chunk cleared completion claims. The 65-frame and 64MiB aggregate boundaries flushed observations as partial without authoritative roots.
- A standalone agent connected to the actual Phoenix endpoint in a shared SQL sandbox with a disposable organization/token. Observed persisted first heartbeat/capabilities; two recurring PING/HTTP intervals; changed credentials/interval; one-shot discovery; candidate probe indexes 1, 0 and -1; restart/reconnect and fresh work; final-assignment/check removal stopping execution. The rejected-token CLI scenario started no work.
- A real controlled SSH peer exercised the server-built custom exec plan: backup content and decompressed byte count persisted correctly, PROBE produced no version, and a mismatched host identity persisted a structured `host_key_mismatch` failure. No physical router or production organization was used.
- Ran the actual CI notification script against the isolated HTTP endpoint: signed request accepted; changed body and absent signature rejected. The server also rejected an expired signature and its successful request queued an available release worker in manual Oban mode.
- A controlled HTTPS download exercised checksum rejection without binary replacement, followed by verified replacement/re-exec of a disposable standalone binary and persistence of its new version heartbeat. The developer's installed executable was not changed.
- Both actual release images also joined the real Phoenix endpoint with correct architecture/container heartbeat metadata and refused standalone self-update. ARM execution used the explicitly documented emulator-only harness mounts and ptrace-compatible smoke configuration, not a changed production image.

### Release image evidence

| Architecture | Verified image digest | Build / execution method |
|---|---|---|
| amd64 | `sha256:a2581e453c4f3eace1e741b4fbbf3218d571441a218bfe59c520375df1c3281d` | Fresh pull and normal Dockerfile build with Podman; native execution |
| arm64 | `sha256:fdee84517344e86ed581fa3363522dc080b7bd4e6432b042e7c003f7ba6b2ecf` | Native Go cross-compilation; unchanged Dockerfile runtime instructions executed under PRoot/QEMU, then actual ARM image execution under emulation |

Resolved base-image platform manifests:

| Base | Observed digest |
|---|---|
| Wolfi amd64 | `sha256:030e45cb37187dff322bbefe9658bcaec31b824a5d523380771a64864c9f45d4` |
| Wolfi arm64 | `sha256:e02c7a98dc477e32e2f04ea2e827a132baace0fbeccb3781aa9c64ffc7982774` |
| Go/Alpine builder amd64 | `sha256:3b15ba438c60ab8fabe5fee3b11025c0049e358b31feff384648f11fc8e335f8` |

Both images ran as UID 1000, wrote persistent bind-mounted data, printed actual CLI help, executed ICMP and supplied their installed APK inventories. The emulator is mounted only for smoke, not included in either image. No native ARM runner or kernel binfmt handler was available; no native ARM CI result is claimed.

The image capability contract is unchanged. Rootless Podman initially refused execution without the binary's required capability; adding the documented `NET_RAW` bounding capability made both runtime probes succeed. README now distinguishes executable capability requirements from fallback behavior after startup.

Grype 0.119.0 scanned both exported OCI archives with the existing `.grype.yaml` and `--fail-on high`. Its refreshed database was built `2026-10-16T06:29:51Z`; both reports contained zero matches and zero ignored matches. Runtime inventories include fresh Wolfi packages, iputils `20250605-r7`, libcap `2.78-r4` and CA bundle `20260909-r2`.

### Rollout boundary

This apply updates the agent and sibling server working trees. No commit, push, release publication or production deployment is performed. Ship the server codec/reassembly corrections before the upgraded agent; preserve TLS, HMAC, checksums and vulnerability gates during rollout or rollback.

Disposable scripts, credentials, certificates and export/scan artifacts were removed; controlled HTTP, SNMP, SSH, HTTPS and Phoenix services were stopped. The development database container was restored to its original stopped state. Verified local amd64/arm64 image tags remain available for inspection; no broad image/cache pruning was performed.
