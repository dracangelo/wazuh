#!/usr/bin/env bash
# Creates, modifies, then deletes a file in a Wazuh-syscheck-monitored directory (default /etc).
# Needs passwordless sudo on the target. Realtime FIM must be enabled for fast alerts,
# otherwise alerts appear only on the next scheduled scan (raise timeout_seconds).
DIR="${1:-/etc}"; F="$DIR/dv_fim_test.txt"
sudo -n sh -c "echo created > '$F' && sleep 3 && echo modified >> '$F' && sleep 3 && rm -f '$F'"
echo "fim events generated in $DIR"
