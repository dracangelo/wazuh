#!/usr/bin/env bash
# Sends well-known attack *signature strings* to a LAB web server so access-log rules can be tested.
# Nothing is exploited: payloads are inert markers. Usage: web_probes.sh <host> <port> <probe>
# probes: scanner | traversal | sqli | webshell | log4shell | canary (benign pipeline marker)
HOST="${1:?host required}"; PORT="${2:-80}"; PROBE="${3:?probe required}"
# Safety: lab use only. Literal private/loopback IPv4 or localhost; anything else is refused.
if ! declare -F dv_require_lab_host >/dev/null 2>&1; then
  . "$(dirname "$0")/../lib/dv_safety.sh" 2>/dev/null || { echo "dv_safety.sh not found" >&2; exit 1; }
fi
dv_require_lab_host "$HOST"
B="http://$HOST:$PORT"; C=(curl -s -o /dev/null -m 5 --path-as-is)
case "$PROBE" in
  scanner)   "${C[@]}" -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "$B/" ;;
  traversal) "${C[@]}" "$B/index.php?page=../../../../etc/passwd" ;;
  sqli)      "${C[@]}" "$B/item.php?id=1%20UNION%20SELECT%20NULL,NULL" ;;
  webshell)  "${C[@]}" "$B/uploads/dv.php?cmd=whoami" ;;
  log4shell) "${C[@]}" -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1/dv}' "$B/" ;;
  canary)    "${C[@]}" "$B/dv_canary" ;;
  *) echo "unknown probe: $PROBE" >&2; exit 2 ;;
esac
echo "probe $PROBE sent to $HOST:$PORT"
