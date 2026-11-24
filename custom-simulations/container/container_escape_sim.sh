#!/usr/bin/env bash
# ==============================================================================
# container_escape_sim.sh - Benign simulation of container breakout vectors
# Usage: container_escape_sim.sh <docker_sock | priv_container | k8s_token>
# ==============================================================================
set -eu

SCENARIO="${1:-docker_sock}"

case "$SCENARIO" in
  docker_sock)
    # Checks for existence of docker.sock without invoking commands
    ls -l /var/run/docker.sock 2>/dev/null || echo "docker.sock inspected"
    ;;
  priv_container)
    # Dry-run / syntax check invoking docker command with privileged flag
    if command -v docker >/dev/null 2>&1; then
      docker run --help | grep -- "--privileged" >/dev/null || true
    else
      echo "docker binary simulated"
    fi
    ;;
  k8s_token)
    # Check for serviceaccount token path
    cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "k8s token checked"
    ;;
  *)
    echo "Unknown scenario: $SCENARIO" >&2
    exit 2
    ;;
esac

echo "container_escape_sim: simulated $SCENARIO"

