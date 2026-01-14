#!/bin/sh
set -e

# Ensure /data directory exists and has proper permissions
if [ -d /data ]; then
  # Fix ownership if needed
  chown -R towerops:towerops /data
fi

# Drop to towerops user and run the agent
exec su-exec towerops towerops-agent "$@"
