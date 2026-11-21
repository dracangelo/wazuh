#!/usr/bin/env bash
# Generates N failed SSH logins for non-existent users against a LAB host.
# Usage: ssh_failed_logins.sh <host> [count=10]   (no passwords are guessed; connections are rejected)
HOST="${1:?host required}"; COUNT="${2:-10}"

# Safety: lab use only. Refuse anything that is not a private/loopback address.
case "$HOST" in
  127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|localhost) ;;
  *) echo "refusing non-lab target: $HOST" >&2; exit 64 ;;
esac
for i in $(seq 1 "$COUNT"); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "dv_invalid_user_$i@$HOST" true 2>/dev/null || true
  sleep 1
done
echo "sent $COUNT failed login attempts to $HOST"
