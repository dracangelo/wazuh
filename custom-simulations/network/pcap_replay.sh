#!/usr/bin/env bash
# ==============================================================================
# pcap_replay.sh - Network IDS simulation & Suricata PCAP Replayer
# Usage: pcap_replay.sh <cobalt_strike | sliver | dns_tunnel> [interface=eth0]
# ==============================================================================
set -eu

ATTACK_TYPE="${1:-cobalt_strike}"
IFACE="${2:-eth0}"

case "$ATTACK_TYPE" in
  cobalt_strike)
    # Generates HTTP request matching default malleable C2 profile URI patterns
    curl -s -m 2 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "http://127.0.0.1:8080/submit.php?id=beacon" 2>/dev/null || true
    ;;
  sliver)
    # Simulates Sliver C2 HTTP session initialization pattern
    curl -s -m 2 -H "User-Agent: Go-http-client/1.1" "http://127.0.0.1:8080/api/v1/session" 2>/dev/null || true
    ;;
  dns_tunnel)
    # Generates high-entropy multi-label DNS query (iodine / dnscat2 simulation)
    dig @127.0.0.1 -p 53 "a1b2c3d4e5f6g7h8i9j0.tunnel.lab.local" +time=1 +tries=1 2>/dev/null || true
    ;;
  *)
    echo "Unknown attack type: $ATTACK_TYPE" >&2
    exit 2
    ;;
esac

echo "pcap_replay: simulated network traffic pattern for $ATTACK_TYPE"

