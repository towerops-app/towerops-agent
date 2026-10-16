# Spec Delta

## Purpose

Keep the agent's released binary and container current with stable upstream dependencies while preserving supported operation and verifiable release safety.

## ADDED Requirements

### Requirement: Stable dependency currency

The agent release SHALL use the latest stable versions available at its recorded resolution time for direct/indirect dependencies, the build toolchain, CI integrations and development tools, including necessary major-version migrations. Intentional rolling sources SHALL be refreshed. Completion evidence SHALL distinguish upgraded, already-current and unresolved dependencies.

#### Scenario: A newer stable dependency exists

- **WHEN** an upstream dependency has published a newer stable release at resolution time
- **THEN** the upgrade adopts that release and migrates affected consumers before declaring completion
- **AND** a prerelease does not displace a stable release merely because its version sorts higher
- **AND** a new major release is evaluated rather than silently excluded

#### Scenario: A dependency intentionally tracks a rolling upstream

- **WHEN** a dependency follows an established rolling image tag or development-tool package channel
- **THEN** the upgrade refreshes that source and records its resolved revision or image evidence without inventing a stable semantic version

#### Scenario: A dependency already uses the latest stable release

- **WHEN** upstream evidence shows the declared dependency is current
- **THEN** the upgrade records that evidence and leaves the declaration unchanged unless its existing version policy must change for compatibility

#### Scenario: An upstream source cannot be resolved

- **WHEN** a version or image source cannot be queried or a target cannot support the required runtime
- **THEN** the completion evidence identifies the unresolved dependency and exact prerequisite or incompatibility
- **AND** the upgrade does not silently substitute an older version or claim full currency

### Requirement: Compatible build and development environments

The supported development environment and CI/container builds SHALL compile the agent using the supported stable Go release line and compatible linting and protobuf generation tools. Generated protocol bindings SHALL retain the canonical server wire contract.

#### Scenario: Toolchain or generator upgrade

- **WHEN** an upgrade changes the compiler, linter or protocol generation tools
- **THEN** a clean development environment can regenerate bindings and build the agent
- **AND** the resulting wire messages remain interoperable with the supported Towerops server

### Requirement: Release safety is preserved

Updated release artifacts SHALL retain the existing architecture support, non-root container operation, persistent device trust store, network capabilities and vulnerability severity gate. Dependency updates SHALL NOT weaken authentication or device identity verification to accommodate upstream changes.

#### Scenario: Updated runtime image

- **WHEN** the release image is rebuilt from refreshed upstream sources
- **THEN** the agent runs without root, retains its persisted device trust store and executes supported network probes
- **AND** each released architecture passes the existing high-and-critical vulnerability gate under the documented exception policy
