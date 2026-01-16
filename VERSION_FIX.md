# Agent Version Update Fix

## Problem

The agent's version checking wasn't working properly because:

1. **Cargo.toml** had hardcoded version `0.1.0`
2. **Binary** had `0.1.0` baked in at compile time via `env!("CARGO_PKG_VERSION")`
3. **Docker images** were tagged with Cargo.toml version
4. **Git tags** (for releases) used different versions than Cargo.toml
5. Result: Version mismatch between binary version and actual Docker image tag

## Solution

Implemented **dynamic version injection** via `build.rs`:

### How It Works

1. **During Build** (`build.rs`):
   - Checks if building from a git tag → use tag version (e.g., `v0.2.0` → `0.2.0`)
   - Checks commit hash → use Cargo version + hash (e.g., `0.1.0-831588e`)
   - Fallback → use Cargo.toml version (`0.1.0`)
   - Injects version as `BUILD_VERSION` env var

2. **In Code** (`version.rs`):
   - Uses `BUILD_VERSION` if available
   - Falls back to `CARGO_PKG_VERSION`
   - Version computed at runtime (not compile-time const)

### Version Formats

| Build Context | Version Format | Example |
|---------------|----------------|---------|
| Git tag (release) | `X.Y.Z` (stripped 'v') | `0.2.0` |
| Dev build | `X.Y.Z-HASH` | `0.1.0-831588e` |
| No git | `X.Y.Z` | `0.1.0` |

### CI/CD Integration

**For Main Branch** (`.gitlab-ci.yml` line 71):
```bash
VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
# Tags: gmcintire/towerops-agent:0.1.0, :latest
```

**For Git Tags** (`.gitlab-ci.yml` line 104):
```bash
VERSION=${CI_COMMIT_TAG#v}  # Strips 'v' prefix
# Tags: gmcintire/towerops-agent:0.2.0, :v0.2.0, :latest
```

**Binary Version** (via `build.rs`):
- On tag: Uses git tag → `0.2.0`
- On main: Uses Cargo.toml → `0.1.0`
- Both match their Docker image tags!

## Testing

### Local Development
```bash
# Build shows version with commit hash
cargo build --release

# Binary reports: 0.1.0-831588e
# (if not on a tag)
```

### After Git Tag
```bash
# Create tag
git tag v0.2.0

# Build
cargo build --release

# Binary reports: 0.2.0
# Matches Docker image: gmcintire/towerops-agent:0.2.0
```

### Version Check
```bash
# Run agent (will check Docker Hub on startup)
cargo run -- --api-url http://localhost:4000 --token <token>

# Logs should show:
# Current version: 0.1.0-831588e
# ✓ Running latest version (or newer available)
```

## Deployment Workflow

### Releasing New Version

1. **Update Cargo.toml version**:
   ```toml
   [package]
   version = "0.2.0"  # <-- Update this
   ```

2. **Commit and tag**:
   ```bash
   git add Cargo.toml
   git commit -m "chore: bump version to 0.2.0"
   git tag v0.2.0
   git push origin main --tags
   ```

3. **CI automatically**:
   - Builds Docker image
   - Binary has version `0.2.0` (from git tag)
   - Tags image as `:0.2.0` and `:latest`

4. **Agent detects update**:
   - Queries Docker Hub tags
   - Finds `0.2.0` > current version
   - Pulls new image and restarts

### Version Bumping Strategy

Use semantic versioning:
- **Patch** (0.1.0 → 0.1.1): Bug fixes
- **Minor** (0.1.0 → 0.2.0): New features
- **Major** (0.1.0 → 1.0.0): Breaking changes

Always bump Cargo.toml **before** creating git tag.

## Files Modified

1. **`build.rs`** - Added version injection logic
2. **`src/version.rs`** - Changed to use BUILD_VERSION
3. **`.gitlab-ci.yml`** - Already correct (no changes needed)

## Benefits

✅ Binary version matches Docker image tag
✅ Auto-updates work correctly
✅ Dev builds show commit hash
✅ Release builds show clean version
✅ No manual version syncing needed

## Next Steps

1. **Bump version to 0.2.0** when ready for next release
2. **Create git tag** (`git tag v0.2.0`)
3. **Push tag** → CI builds and publishes
4. **Deployed agents** detect and auto-update

---

**Status**: ✅ Fixed
**Date**: January 16, 2026
**Issue**: Version checking now works correctly with git-based versioning
