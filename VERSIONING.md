# Agent Versioning

The towerops-agent uses **semantic versioning** (semver) to track releases and enable automatic update detection.

## Version Format

Versions follow the format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes (API incompatibility)
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

## Current Version

The version is defined in `Cargo.toml`:

```toml
[package]
version = "0.1.0"
```

This is the **source of truth** for the agent's version.

## Bumping Versions

Use the provided script to increment the version:

```bash
# Patch release (0.1.0 -> 0.1.1) - bug fixes
./scripts/bump-version.sh patch

# Minor release (0.1.0 -> 0.2.0) - new features
./scripts/bump-version.sh minor

# Major release (0.1.0 -> 1.0.0) - breaking changes
./scripts/bump-version.sh major
```

The script will:
1. ✅ Update `Cargo.toml` with new version
2. ✅ Update `Cargo.lock`
3. ✅ Create git commit
4. ✅ Create git tag (e.g., `v0.1.1`)

Then push:
```bash
git push origin main
git push origin v0.1.1  # Push the tag
```

## CI/CD Pipeline

When you push to main or push a tag, GitLab CI automatically:

### On Main Branch Push
- Builds Docker image for `linux/amd64`
- Extracts version from `Cargo.toml`
- Tags image with:
  - `:latest` (always)
  - `:0.1.0` (version from Cargo.toml)
  - `:main-abc123` (commit SHA)
- Pushes to Docker Hub

### On Git Tag Push (e.g., `v0.1.0`)
- Builds multi-arch Docker image (`linux/amd64`, `linux/arm64`)
- Tags image with:
  - `:0.1.0` (extracted from tag)
  - `:v0.1.0` (original tag name)
  - `:latest` (always)
- Pushes to Docker Hub

## Version Checking

The agent checks Docker Hub for newer versions:

### At Startup
```
[INFO] Current version: 0.1.0
[INFO] ✓ Running latest version (0.1.0)
```

Or if outdated:
```
[INFO] Current version: 0.1.0
[WARN] ⚠️  Newer version available: 0.2.0 (current: 0.1.0)
[WARN]    Automatic updates will pull new version every hour
```

### Every Hour
The agent checks Docker Hub for newer semver tags and automatically pulls if a newer version is available.

## How It Works

1. **Agent queries Docker Hub**: `GET /v2/repositories/gmcintire/towerops-agent/tags?page_size=100`
2. **Filters for semver tags**: Only considers tags matching `X.Y.Z` format
3. **Compares versions**: Uses semver comparison (`0.2.0` > `0.1.0`)
4. **Pulls if newer**: If newer version exists, runs `docker pull gmcintire/towerops-agent:latest`
5. **Restarts**: Exits with code 0, docker-compose/k8s restarts with new image

## Docker Hub Tags

After a few releases, you'll see:

```
gmcintire/towerops-agent:latest         # Always newest
gmcintire/towerops-agent:0.2.0          # Specific version
gmcintire/towerops-agent:0.1.1          # Previous version
gmcintire/towerops-agent:0.1.0          # Original version
gmcintire/towerops-agent:main-abc123    # Commit SHA (transient)
```

## Version History

### 0.1.0 (Initial Release)
- SNMP polling with sensors and interfaces
- Protocol Buffers API communication
- SQLite buffering with 24h retention
- Automatic Docker self-updates
- Health endpoint on port 8080

## Best Practices

### When to Bump

- **Patch** (0.1.0 → 0.1.1)
  - Bug fixes
  - Performance improvements
  - Documentation updates
  - Internal refactoring

- **Minor** (0.1.0 → 0.2.0)
  - New SNMP OID support
  - New metric types
  - New configuration options
  - New features (backwards compatible)

- **Major** (0.1.0 → 1.0.0)
  - Protocol Buffers schema changes (breaking)
  - Configuration format changes
  - API endpoint changes
  - Removal of deprecated features

### Release Checklist

Before bumping version:

- [ ] All tests passing: `cargo test`
- [ ] No clippy warnings: `cargo clippy`
- [ ] Code formatted: `cargo fmt`
- [ ] CHANGELOG.md updated (if exists)
- [ ] Breaking changes documented
- [ ] Migration guide written (for major versions)

### Rolling Back

If you need to roll back to a previous version:

```bash
# Update docker-compose.yml to pin specific version
services:
  towerops-agent:
    image: gmcintire/towerops-agent:0.1.0  # Pin to specific version
```

Or via environment variable:
```bash
AGENT_VERSION=0.1.0 docker-compose up -d
```

## Troubleshooting

### "No valid semver tags found"
- No version tags exist on Docker Hub yet
- Push a version tag: `./scripts/bump-version.sh patch && git push --tags`

### "Could not check for updates"
- Docker Hub API unreachable
- Network connectivity issue
- Agent continues to run normally

### Auto-update not working
- Check Docker socket is mounted: `-v /var/run/docker.sock:/var/run/docker.sock`
- Check container has permissions: `docker logs <container>`
- Verify using `:latest` tag, not pinned version

### Agent always pulling but not restarting
- `docker pull` succeeds but shows "Image is up to date"
- This is correct behavior - only restarts if new image downloaded
- Agent is already running the latest version

## Development

During development, disable auto-updates by running without Docker socket:

```bash
cargo run -- \
  --api-url http://localhost:4000 \
  --token <token>
```

Or run in Docker without socket mount:
```yaml
services:
  towerops-agent:
    image: gmcintire/towerops-agent:latest
    # Don't mount socket during dev
    # volumes:
    #   - /var/run/docker.sock:/var/run/docker.sock
```

This prevents auto-updates during development/testing.
