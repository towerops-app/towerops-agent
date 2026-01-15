#!/bin/sh
set -e

# Ensure /data directory exists and has proper permissions
if [ -d /data ]; then
  # Fix ownership if needed
  chown -R towerops:towerops /data
fi

# If Docker socket is mounted, add towerops user to docker group
if [ -S /var/run/docker.sock ]; then
  # Get the GID of the docker socket
  DOCKER_GID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || stat -f '%g' /var/run/docker.sock 2>/dev/null)

  # Create docker group with the same GID as host's docker socket
  if ! getent group "$DOCKER_GID" >/dev/null 2>&1; then
    addgroup -g "$DOCKER_GID" docker
  fi

  # Add towerops user to the docker group
  addgroup towerops docker 2>/dev/null || true
fi

# Drop to towerops user and run the agent
exec su-exec towerops towerops-agent "$@"
