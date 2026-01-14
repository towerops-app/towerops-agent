# Release Process for Towerops Agent

This document describes how to build, tag, and publish releases of the Towerops agent Docker image.

## Prerequisites

- Podman or Docker installed
- Access to container registry (Docker Hub, GitHub Container Registry, GitLab Registry, etc.)
- Agent code built and tested

## Version Numbering

Follow semantic versioning (SemVer):
- **MAJOR**: Incompatible API/protocol changes
- **MINOR**: New functionality, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

Current version: **0.1.0**

## Build Process

### 1. Update Version Numbers

Before building a release, update version numbers in:

1. **Cargo.toml**:
```toml
[package]
name = "towerops-agent"
version = "0.1.0"  # Update this
```

2. **CLAUDE.md** - Update status section

3. **README.md** - Update any version references

### 2. Build Multi-Architecture Images

Build for both AMD64 and ARM64:

```bash
cd /Users/graham/dev/towerops/towerops-agent

# Build for ARM64 (Apple Silicon)
podman build --platform linux/arm64 -t towerops-agent:0.1.0-arm64 .

# Build for AMD64 (Intel/AMD)
podman build --platform linux/amd64 -t towerops-agent:0.1.0-amd64 .
```

### 3. Tag Images

Tag with version and 'latest':

```bash
# Tag ARM64
podman tag towerops-agent:0.1.0-arm64 localhost/towerops-agent:0.1.0
podman tag towerops-agent:0.1.0-arm64 localhost/towerops-agent:latest

# Tag AMD64
podman tag towerops-agent:0.1.0-amd64 localhost/towerops-agent:0.1.0-amd64
```

### 4. Test Images Locally

Before publishing, test both images:

```bash
# Test ARM64
podman run --rm \
  -e TOWEROPS_API_URL=http://localhost:4000 \
  -e TOWEROPS_AGENT_TOKEN=test-token \
  localhost/towerops-agent:0.1.0 --version

# Test AMD64 (if on compatible platform)
podman run --rm --platform linux/amd64 \
  -e TOWEROPS_API_URL=http://localhost:4000 \
  -e TOWEROPS_AGENT_TOKEN=test-token \
  localhost/towerops-agent:0.1.0-amd64 --version
```

## Publishing to Container Registries

### Option 1: Docker Hub

**Registry**: `docker.io/username/towerops-agent`

1. **Login**:
```bash
podman login docker.io
# Enter username and password/token
```

2. **Tag for Docker Hub**:
```bash
# Replace 'username' with your Docker Hub username
DOCKER_USER="username"

podman tag localhost/towerops-agent:0.1.0 docker.io/${DOCKER_USER}/towerops-agent:0.1.0
podman tag localhost/towerops-agent:latest docker.io/${DOCKER_USER}/towerops-agent:latest
podman tag localhost/towerops-agent:0.1.0-amd64 docker.io/${DOCKER_USER}/towerops-agent:0.1.0-amd64
```

3. **Push**:
```bash
podman push docker.io/${DOCKER_USER}/towerops-agent:0.1.0
podman push docker.io/${DOCKER_USER}/towerops-agent:latest
podman push docker.io/${DOCKER_USER}/towerops-agent:0.1.0-amd64
```

4. **Create multi-arch manifest** (optional, for `docker pull` without specifying platform):
```bash
podman manifest create docker.io/${DOCKER_USER}/towerops-agent:0.1.0
podman manifest add docker.io/${DOCKER_USER}/towerops-agent:0.1.0 docker.io/${DOCKER_USER}/towerops-agent:0.1.0-arm64
podman manifest add docker.io/${DOCKER_USER}/towerops-agent:0.1.0 docker.io/${DOCKER_USER}/towerops-agent:0.1.0-amd64
podman manifest push docker.io/${DOCKER_USER}/towerops-agent:0.1.0
```

### Option 2: GitHub Container Registry (ghcr.io)

**Registry**: `ghcr.io/username/towerops-agent`

1. **Create Personal Access Token**:
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate new token with `write:packages` and `read:packages` scopes
   - Save the token securely

2. **Login**:
```bash
echo $GITHUB_TOKEN | podman login ghcr.io -u USERNAME --password-stdin
```

3. **Tag for GHCR**:
```bash
GITHUB_USER="username"

podman tag localhost/towerops-agent:0.1.0 ghcr.io/${GITHUB_USER}/towerops-agent:0.1.0
podman tag localhost/towerops-agent:latest ghcr.io/${GITHUB_USER}/towerops-agent:latest
```

4. **Push**:
```bash
podman push ghcr.io/${GITHUB_USER}/towerops-agent:0.1.0
podman push ghcr.io/${GITHUB_USER}/towerops-agent:latest
```

5. **Make Package Public** (optional):
   - Go to package settings on GitHub
   - Change visibility to public

### Option 3: GitLab Container Registry

**Registry**: `registry.gitlab.com/username/towerops-agent`

1. **Create Deploy Token or Personal Access Token**:
   - GitLab Project → Settings → Repository → Deploy tokens
   - Or use personal access token with `read_registry` and `write_registry` scopes

2. **Login**:
```bash
podman login registry.gitlab.com
# Username: your GitLab username or deploy token name
# Password: personal access token or deploy token
```

3. **Tag for GitLab**:
```bash
GITLAB_USER="username"

podman tag localhost/towerops-agent:0.1.0 registry.gitlab.com/${GITLAB_USER}/towerops-agent:0.1.0
podman tag localhost/towerops-agent:latest registry.gitlab.com/${GITLAB_USER}/towerops-agent:latest
```

4. **Push**:
```bash
podman push registry.gitlab.com/${GITLAB_USER}/towerops-agent:0.1.0
podman push registry.gitlab.com/${GITLAB_USER}/towerops-agent:latest
```

### Option 4: Self-Hosted Registry

**Registry**: `registry.example.com/towerops-agent`

1. **Login** (if authentication required):
```bash
podman login registry.example.com
```

2. **Tag**:
```bash
podman tag localhost/towerops-agent:0.1.0 registry.example.com/towerops-agent:0.1.0
podman tag localhost/towerops-agent:latest registry.example.com/towerops-agent:latest
```

3. **Push**:
```bash
podman push registry.example.com/towerops-agent:0.1.0
podman push registry.example.com/towerops-agent:latest
```

## Git Release Tagging

After publishing the Docker images:

1. **Commit all changes**:
```bash
git add -A
git commit -m "Release v0.1.0"
```

2. **Create and push git tag**:
```bash
git tag -a v0.1.0 -m "Release v0.1.0 - Initial production release"
git push origin v0.1.0
git push origin main
```

3. **Create GitHub/GitLab Release**:
   - Go to repository releases page
   - Create new release from tag v0.1.0
   - Add release notes (see template below)

## Release Notes Template

```markdown
# Towerops Agent v0.1.0

## Features

- Remote SNMP polling for Towerops equipment
- Protocol Buffers API communication
- SQLite-based metric buffering (24-hour retention)
- Automatic reconnection and retry logic
- Multi-architecture support (AMD64, ARM64)
- Minimal footprint: 11.8 MB Docker image

## Configuration

- API URL and authentication token via environment variables
- Configurable poll intervals per equipment
- Customizable database path

## Installation

```bash
docker pull ghcr.io/username/towerops-agent:0.1.0
```

See [USER_GUIDE.md](USER_GUIDE.md) for deployment instructions.

## System Requirements

- Docker or Podman
- Network access to Towerops API
- Network access to SNMP devices (UDP port 161)
- 50-100 MB disk space for database

## Breaking Changes

None (initial release)

## Known Issues

None

## Contributors

- [List contributors]
```

## CI/CD Automation (Optional)

### GitLab CI Example

Create `.gitlab-ci.yml`:

```yaml
variables:
  REGISTRY_IMAGE: $CI_REGISTRY_IMAGE

stages:
  - test
  - build
  - release

test:
  stage: test
  image: rust:1.83-alpine
  before_script:
    - apk add --no-cache musl-dev protobuf-dev
  script:
    - cargo test --release
  only:
    - branches

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA .
    - docker push $REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  only:
    - main

release:
  stage: release
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker pull $REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
    - docker tag $REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA $REGISTRY_IMAGE:$CI_COMMIT_TAG
    - docker tag $REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA $REGISTRY_IMAGE:latest
    - docker push $REGISTRY_IMAGE:$CI_COMMIT_TAG
    - docker push $REGISTRY_IMAGE:latest
  only:
    - tags
```

### GitHub Actions Example

Create `.github/workflows/release.yml`:

```yaml
name: Build and Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract version from tag
        id: version
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ steps.version.outputs.VERSION }}
            ghcr.io/${{ github.repository }}:latest
```

## Verification After Release

1. **Test pulling image**:
```bash
podman pull ghcr.io/username/towerops-agent:0.1.0
```

2. **Verify image size**:
```bash
podman images towerops-agent
# Should be ~11-12 MB
```

3. **Test image runs**:
```bash
podman run --rm ghcr.io/username/towerops-agent:0.1.0 --help
```

4. **Update documentation**:
   - Update USER_GUIDE.md with new image URL
   - Update example docker-compose files
   - Update Phoenix UI modal with new image reference

## Rollback Procedure

If a release has critical issues:

1. **Revert 'latest' tag** to previous version:
```bash
# Find previous working version
podman pull ghcr.io/username/towerops-agent:0.0.9

# Re-tag as latest
podman tag ghcr.io/username/towerops-agent:0.0.9 ghcr.io/username/towerops-agent:latest

# Push
podman push ghcr.io/username/towerops-agent:latest
```

2. **Notify users**:
   - Update release notes with issue details
   - Mark release as "yanked" or pre-release
   - Provide migration path or workaround

3. **Fix and re-release**:
   - Fix issues in code
   - Release as patch version (e.g., 0.1.1)

## Release Checklist

Before each release:

- [ ] All tests passing (`cargo test`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Version numbers updated in Cargo.toml, CLAUDE.md
- [ ] CHANGELOG.md updated with release notes
- [ ] Docker images build successfully for both platforms
- [ ] Images tested locally with sample configuration
- [ ] Integration tests pass (if available)
- [ ] Documentation updated
- [ ] Git commit and tag created
- [ ] Images pushed to registry
- [ ] GitHub/GitLab release created with notes
- [ ] Verify images are publicly accessible
- [ ] Notify stakeholders of release

## Support

For issues with releases:
- Open an issue on GitHub/GitLab
- Check TROUBLESHOOTING.md in USER_GUIDE
- Review logs from agent: `podman logs <container-id>`
