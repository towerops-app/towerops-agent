# Spec Delta

## Purpose

Preserve operational interoperability between the Go agent and Towerops' authenticated Phoenix agent channel across dependency and toolchain upgrades.

## ADDED Requirements

### Requirement: Canonical interoperable wire contract

The agent SHALL implement the canonical Towerops server agent protocol without changing existing field numbers, types, enum values, reserved identifiers or supported event envelopes incompatibly. Messages produced by either side SHALL decode on the other side with their intended values, including supported optional fields and default values. Agreement between schema copies or a codec's own round trip alone SHALL NOT establish interoperability.

#### Scenario: Server work reaches the agent

- **WHEN** the supported Towerops server sends recurring work, checks, a configuration-backup plan or a credential probe
- **THEN** the agent decodes the actual server-produced bytes and executes the supported operation using the intended credentials, configuration and correlation identifiers

#### Scenario: Agent results reach the server

- **WHEN** the agent sends a supported heartbeat, monitoring result, trap, backup result, credential result or error
- **THEN** the supported server decodes the actual agent-produced bytes and retains the intended values and result correlation
- **AND** new optional data does not invalidate older supported messages that omit it

### Requirement: Authenticated channel lifecycle

The agent SHALL use the configured Towerops agent WebSocket endpoint and existing Phoenix framing. Authentication rejection SHALL prevent work from starting. Heartbeats SHALL accurately advertise implemented capabilities so the server can select supported behavior.

#### Scenario: Rejected token

- **WHEN** the server rejects the agent's channel join
- **THEN** the session starts no work executors and exposes the authentication failure without leaking the token

#### Scenario: Successful connection

- **WHEN** a valid agent joins its channel
- **THEN** the server accepts its heartbeat and capability fields and sends work using the supported event names and payload envelopes

### Requirement: Authoritative recurring inventories

For an agent advertising local scheduling, complete job and check inventories SHALL replace the respective recurring schedules. An explicit empty inventory SHALL remove that group's assignments. Malformed input SHALL NOT erase valid work. One-shot requests SHALL NOT replace recurring schedules. Disconnect SHALL discard credential-bearing assignments, and reconnect SHALL require fresh authenticated inventories.

#### Scenario: Assignment removed

- **WHEN** the server sends an explicit empty inventory after the last assignment is removed
- **THEN** the agent stops that group's recurring work without stopping unrelated groups

#### Scenario: Unchanged or changed inventory

- **WHEN** the server refreshes an unchanged inventory or replaces an assignment's configuration or interval
- **THEN** unchanged assignments retain their schedule and changed assignments execute with the new configuration without overlapping their predecessor

#### Scenario: Reconnect

- **WHEN** the WebSocket connection is lost and subsequently re-established
- **THEN** stale assignments and credentials are not reused and fresh inventories establish the new schedule

### Requirement: Result and size-boundary compatibility

The agent and server SHALL agree on supported message envelopes and effective size boundaries for accepted inputs and produced outputs. Oversized or malformed messages SHALL fail observably without silently truncating a result into a different successful measurement. Result replay SHALL retain the documented delivery semantics rather than imply server acknowledgement that the protocol does not provide.

#### Scenario: Large supported payload

- **WHEN** either side sends a valid payload within the documented effective limits
- **THEN** the peer accepts and decodes the complete payload, including base64 and envelope overhead where applicable

#### Scenario: Completed result during reconnect

- **WHEN** a completed result is queued while the connection is unavailable
- **THEN** reconnect preserves its routing and correlation under the existing bounded-spool delivery contract
- **AND** completion evidence does not claim exactly-once or acknowledged delivery

### Requirement: Authenticated release notification

Release automation SHALL notify Towerops through its existing agent-release endpoint using both the configured bearer secret and the server-required timestamped HMAC signature over the exact transmitted body. The receiver's authentication and replay protections SHALL NOT be relaxed to accommodate the sender.

#### Scenario: Valid release notification

- **WHEN** release automation sends a notification with a current timestamp and matching bearer and HMAC credentials
- **THEN** Towerops accepts the notification and enqueues its release-update worker
- **AND** the signature uses the exact body bytes sent, including the empty body if no payload is supplied

#### Scenario: Invalid or stale release notification

- **WHEN** a notification lacks the required signature, has a mismatched body or falls outside the server's replay window
- **THEN** Towerops rejects it as unauthorized without queuing an update
