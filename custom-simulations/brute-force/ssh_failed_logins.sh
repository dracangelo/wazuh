#!/usr/bin/env bash
# Generates N failed SSH logins for non-existent users against a LAB host.
# Usage: ssh_failed_logins.sh <host> [count=10]   (no passwords are guessed; connections are rejected)
HOST="${1:?host required}"; COUNT="${2:-10}"

# Safety: lab use only. Literal private/loopback IPv4 or localhost; anything else is refused.
if ! declare -F dv_require_lab_host >/dev/null 2>&1; then
  . "$(dirname "$0")/../lib/dv_safety.sh" 2>/dev/null || { echo "dv_safety.sh not found" >&2; exit 1; }
fi
dv_require_lab_host "$HOST"
for i in $(seq 1 "$COUNT"); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "dv_invalid_user_$i@$HOST" true 2>/dev/null || true
  sleep 1
done
echo "sent $COUNT failed login attempts to $HOST"
