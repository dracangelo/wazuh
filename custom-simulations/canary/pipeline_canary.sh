#!/usr/bin/env bash
# Pipeline canary: one benign SSH login attempt as a random nonexistent user on this host.
# sshd logs "Invalid user ...", which Wazuh's built-in sshd rule 5710 detects. Nothing is created
# or changed; a failed login is the intended outcome.
set -u
user="dv_canary_$(date -u +%s)_$$"
timeout 10 ssh -o BatchMode=yes -o ConnectTimeout=5 \
  -o PreferredAuthentications=none -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${user}@127.0.0.1" true >/dev/null 2>&1 || true
exit 0
