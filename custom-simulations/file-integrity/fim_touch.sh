#!/usr/bin/env bash
# Creates, modifies, then deletes a uniquely named file in a Wazuh-syscheck-monitored directory
# (default /etc). Needs passwordless sudo on the target. Realtime FIM must be enabled for fast alerts,
# otherwise alerts appear only on the next scheduled scan (raise timeout_seconds).
#
# The file name carries this execution's id so concurrent or repeated runs cannot collide, and the
# file is recorded before it is written so an interrupted run is still cleaned up. Rules 100100-100102
# match the dv_fim_test*.txt pattern.
if ! declare -F dv_cleanup >/dev/null 2>&1; then
  . "$(dirname "$0")/../lib/dv_safety.sh" 2>/dev/null || { echo "dv_safety.sh not found" >&2; exit 1; }
fi
set -u
DIR="${1:-/etc}"
case "$DIR" in /*) ;; *) echo "directory must be absolute: $DIR" >&2; exit 64 ;; esac
[ -d "$DIR" ] || { echo "not a directory: $DIR" >&2; exit 64; }
F="$DIR/dv_fim_test_$(dv_suffix).txt"
dv_sudo_file "$F" "created" 0644 || exit 1
sleep 3
printf 'modified\n' | sudo -n tee -a -- "$F" >/dev/null
sudo -n rm -f "$F"
echo "fim events generated in $DIR for $(basename "$F")"
