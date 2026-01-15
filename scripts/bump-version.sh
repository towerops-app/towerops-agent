#!/bin/bash

# Bump semantic version in Cargo.toml
# Usage: ./bump-version.sh [major|minor|patch]

set -e

BUMP_TYPE=${1:-patch}

if [[ ! "$BUMP_TYPE" =~ ^(major|minor|patch)$ ]]; then
    echo "Error: Invalid bump type. Use: major, minor, or patch"
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

if [ -z "$CURRENT_VERSION" ]; then
    echo "Error: Could not find version in Cargo.toml"
    exit 1
fi

echo "Current version: $CURRENT_VERSION"

# Parse version
IFS='.' read -r major minor patch <<< "$CURRENT_VERSION"

# Bump version
case $BUMP_TYPE in
    major)
        major=$((major + 1))
        minor=0
        patch=0
        ;;
    minor)
        minor=$((minor + 1))
        patch=0
        ;;
    patch)
        patch=$((patch + 1))
        ;;
esac

NEW_VERSION="$major.$minor.$patch"

echo "New version: $NEW_VERSION"

# Update Cargo.toml
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    # Linux
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi

echo "✓ Updated Cargo.toml"

# Update Cargo.lock
cargo check --quiet
echo "✓ Updated Cargo.lock"

# Git operations
git add Cargo.toml Cargo.lock
git commit -m "Bump version to $NEW_VERSION"
git tag "v$NEW_VERSION"

echo ""
echo "✓ Version bumped to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  git push origin main"
echo "  git push origin v$NEW_VERSION"
echo ""
echo "This will trigger a GitLab CI build that tags the Docker image with $NEW_VERSION"
