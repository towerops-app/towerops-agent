# Towerops Agent - Deployment Guide

## GitLab CI/CD Pipeline

The agent uses GitLab CI/CD to automatically build and publish Docker images to the GitLab Container Registry.

### Pipeline Stages

1. **Test** - Compile, format check, and lint
2. **Build** - Build Docker image
3. **Release** - Tag and publish versioned releases

### Image Tags

| Git Action | Image Tags | Example |
|------------|------------|---------|
| Push to branch | `<branch>`, `<commit-sha>` | `feat-snmp`, `abc123` |
| Push to main | `latest`, `main-<sha>` | `latest`, `main-abc123` |
| Create tag | `<version>`, `<tag>`, `latest` | `0.1.0`, `v0.1.0`, `latest` |

### Registry Location

All images are pushed to:
```
registry.gitlab.com/towerops/towerops-agent
```

## Creating a Release

### 1. Update Version

**In `Cargo.toml`**:
```toml
[package]
name = "towerops-agent"
version = "0.2.0"  # ← Update this
edition = "2021"
```

### 2. Commit and Tag

```bash
git add Cargo.toml
git commit -m "Release v0.2.0"
git tag v0.2.0
git push origin main --tags
```

### 3. CI Pipeline Runs

GitLab CI will automatically:
- Run tests (cargo check, fmt, clippy)
- Build Docker image
- Tag as: `0.2.0`, `v0.2.0`, `latest`
- Push to registry

### 4. Verify Release

Check the Container Registry:
```
https://gitlab.com/towerops/towerops-agent/container_registry
```

You should see:
- `latest` (updated)
- `0.2.0` (new)
- `v0.2.0` (new)

## Using the Images

### Pull Latest

```bash
docker pull registry.gitlab.com/towerops/towerops-agent:latest
```

### Pull Specific Version

```bash
docker pull registry.gitlab.com/towerops/towerops-agent:0.1.0
```

### Docker Compose

Update `docker-compose.yml`:
```yaml
services:
  towerops-agent:
    image: registry.gitlab.com/towerops/towerops-agent:latest
    # Or pin to specific version:
    # image: registry.gitlab.com/towerops/towerops-agent:0.1.0
    environment:
      - TOWEROPS_API_URL=https://app.towerops.com
      - TOWEROPS_AGENT_TOKEN=${AGENT_TOKEN}
    volumes:
      - ./data:/data
```

## Customer Deployment

### Provide to Customers

**Option 1: Docker Compose (Recommended)**

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  towerops-agent:
    image: registry.gitlab.com/towerops/towerops-agent:latest
    container_name: towerops-agent
    restart: unless-stopped
    environment:
      - TOWEROPS_API_URL=https://app.towerops.com
      - TOWEROPS_AGENT_TOKEN=<GET_FROM_UI>
    volumes:
      - ./data:/data
```

Instructions for customer:
```bash
# 1. Get agent token from Towerops UI
# 2. Replace <GET_FROM_UI> in docker-compose.yml
# 3. Start agent
docker-compose up -d

# 4. Check logs
docker-compose logs -f

# 5. Check status
docker-compose ps
```

**Option 2: Docker Run**

```bash
docker run -d \
  --name towerops-agent \
  --restart unless-stopped \
  -e TOWEROPS_API_URL=https://app.towerops.com \
  -e TOWEROPS_AGENT_TOKEN=<token> \
  -v $(pwd)/data:/data \
  registry.gitlab.com/towerops/towerops-agent:latest
```

## CI/CD Configuration

### Required GitLab Variables

No additional CI/CD variables needed. GitLab provides these automatically:
- `CI_REGISTRY` - GitLab Container Registry URL
- `CI_REGISTRY_USER` - Username for registry login
- `CI_REGISTRY_PASSWORD` - Password for registry login

These are automatically available in all GitLab CI/CD pipelines.

### Pipeline Triggers

**Automatic**:
- Push to any branch → test + build with branch tag
- Push to main → test + build + tag as `latest`
- Create tag (e.g., `v0.1.0`) → test + build + release

**Manual**: No manual triggers configured (all automatic)

### Viewing Pipeline Status

1. Go to: https://gitlab.com/towerops/towerops-agent/-/pipelines
2. Click on a pipeline to see detailed logs
3. Check job logs if build fails

## Local Development

### Build Locally

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Build Docker image locally
docker build -t towerops-agent:local .

# Test local image
docker run --rm \
  -e TOWEROPS_API_URL=http://host.docker.internal:4000 \
  -e TOWEROPS_AGENT_TOKEN=test-token \
  -v $(pwd)/test-data:/data \
  towerops-agent:local
```

### Test Before Pushing

**Prerequisites**: Rust 1.83+ (required by dependencies)

```bash
# Check Rust version
rustc --version  # Should be 1.83.0 or later

# Check compilation
cargo check --release

# Format check
cargo fmt -- --check

# Lint check
cargo clippy -- -D warnings

# All together (what CI runs)
cargo check --release && \
cargo fmt -- --check && \
cargo clippy -- -D warnings
```

## Rollback Procedure

### If Latest Version Has Issues

**Option 1: Revert Tag**
```bash
# Find previous working version
git tag -l

# Delete bad tag locally and remotely
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0

# Customers can use previous version
docker pull registry.gitlab.com/towerops/towerops-agent:0.1.0
```

**Option 2: Quick Fix**
```bash
# Fix the issue
git commit -m "Hotfix: fix critical bug"

# Create patch version
git tag v0.2.1
git push origin main --tags

# New pipeline builds v0.2.1 and updates latest
```

**Option 3: Pin Customers to Known Good Version**

Update customer docker-compose.yml:
```yaml
image: registry.gitlab.com/towerops/towerops-agent:0.1.0  # Pin to working version
```

## Multi-Architecture Support (Optional)

To support ARM devices (Raspberry Pi, etc.), uncomment the multi-arch section in `.gitlab-ci.yml`.

This will build for:
- `linux/amd64` (x86_64 servers)
- `linux/arm64` (ARM servers, Raspberry Pi 4+)

**Note**: Multi-arch builds take longer (~2x build time).

## Monitoring Deployments

### Check Image Size

```bash
docker images registry.gitlab.com/towerops/towerops-agent
```

Expected size: 10-20 MB

### Check Registry Usage

GitLab provides 10 GB of free registry storage. Monitor usage at:
```
https://gitlab.com/towerops/towerops-agent/-/packages
```

### Cleanup Old Images

GitLab has automatic cleanup policies. Configure at:
```
Settings → Packages & Registries → Container Registry → Cleanup policies
```

Recommended settings:
- Keep most recent: 10 tags
- Keep tags matching: `^v\d+\.\d+\.\d+$` (versions)
- Remove tags older than: 90 days

## Troubleshooting

### Pipeline Fails with "lock file version not understood"

**Symptom**:
```
error: failed to parse lock file at: /builds/towerops/towerops-agent/Cargo.lock
Caused by:
  lock file version `4` was found, but this version of Cargo does not understand this lock file
```

**Cause**: Dependencies require Rust 1.83+

**Fix**: The CI configuration uses Rust 1.83. If you see this error:
1. Update `.gitlab-ci.yml` to use `rust:1.83-alpine` or later
2. Update `Dockerfile` to use `rust:1.83-alpine` or later
3. Local development: Update Rust with `rustup update stable`

### Pipeline Fails at Test Stage

**Symptom**: `cargo check` or `cargo clippy` fails

**Fix**:
```bash
# Run locally to see errors
cargo check --release
cargo clippy -- -D warnings

# Fix issues and push
git add .
git commit -m "Fix clippy warnings"
git push
```

### Pipeline Fails at Build Stage

**Symptom**: Docker build fails

**Fix**:
```bash
# Test Docker build locally
docker build -t test .

# Check Dockerfile syntax
# Check .dockerignore isn't excluding needed files
```

### Image Too Large

**Symptom**: Image is >50 MB

**Fix**:
- Check release profile in Cargo.toml (should have `strip = true`)
- Verify multi-stage build is working
- Check for large files in context (review .dockerignore)

### Can't Pull Image

**Symptom**: `docker pull` fails with authentication error

**Fix**:
```bash
# Login to GitLab registry
docker login registry.gitlab.com
# Username: your GitLab username
# Password: personal access token with read_registry scope

# Or use deploy token (for customers)
# Create at: Settings → Repository → Deploy tokens
```

## Security

### Container Scanning (Optional)

Add to `.gitlab-ci.yml` for security scanning:

```yaml
include:
  - template: Security/Container-Scanning.gitlab-ci.yml

container_scanning:
  stage: test
  variables:
    CS_IMAGE: $REGISTRY/$IMAGE_NAME:$CI_COMMIT_SHORT_SHA
```

### Private Registry Access

For customers needing private access:

1. Create deploy token:
   - Go to: Settings → Repository → Deploy tokens
   - Name: `customer-deploy-token`
   - Scopes: `read_registry`
   - Copy username and token

2. Provide to customer:
```bash
docker login registry.gitlab.com
# Username: <deploy-token-username>
# Password: <deploy-token>
```

## Support

For issues with deployment:
1. Check pipeline logs in GitLab
2. Review CLAUDE.md for architecture details
3. Test locally with `docker build`
4. Check GitLab registry status page

---

**Last Updated**: January 9, 2026
**Registry**: registry.gitlab.com/towerops/towerops-agent
**Current Version**: 0.1.0 (pre-release)
