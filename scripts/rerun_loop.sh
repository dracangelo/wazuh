#!/usr/bin/env bash
# ==============================================================================
# rerun_loop.sh - Automated watch/rerun loop for continuous detection testing
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INTERVAL="${1:-5}"

echo "=========================================================="
echo " Starting detection tests rerun monitor (Interval: ${INTERVAL}s)"
echo " Watching: rules/, test-catalog/, custom-simulations/, tests/"
echo " Press Ctrl+C to terminate."
echo "=========================================================="

LAST_RUN_SUCCESS=false

run_cycle() {
  clear 2>/dev/null || true
  echo "----------------------------------------------------------"
  echo " Run triggered at: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "----------------------------------------------------------"
  if "${SCRIPT_DIR}/run_tests.sh" --all; then
    LAST_RUN_SUCCESS=true
    echo -e "\n\033[1;32m✔ All checks passed at $(date '+%H:%M:%S')\033[0m"
  else
    LAST_RUN_SUCCESS=false
    echo -e "\n\033[1;31m✘ Checks failed at $(date '+%H:%M:%S')\033[0m"
  fi
}

# Initial run
run_cycle

# File watch loop using find or inotifywait if available
if command -v inotifywait >/dev/null 2>&1; then
  echo "Using inotifywait for instant file event detection..."
  while true; do
    inotifywait -r -q -e modify,create,delete,move \
      "${ROOT_DIR}/rules" \
      "${ROOT_DIR}/test-catalog" \
      "${ROOT_DIR}/custom-simulations" \
      "${ROOT_DIR}/tests" >/dev/null 2>&1 || true
    sleep 1
    run_cycle
  done
else
  echo "inotifywait not installed. Polling directory mtimes every ${INTERVAL}s..."
  GET_MTIME() {
    find "${ROOT_DIR}/rules" "${ROOT_DIR}/test-catalog" "${ROOT_DIR}/custom-simulations" "${ROOT_DIR}/tests" \
      -type f -not -name "*.pyc" -not -path "*/.*" -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1
  }
  PREV_MTIME="$(GET_MTIME)"
  while true; do
    sleep "${INTERVAL}"
    CURR_MTIME="$(GET_MTIME)"
    if [[ "${CURR_MTIME}" != "${PREV_MTIME}" ]]; then
      PREV_MTIME="${CURR_MTIME}"
      run_cycle
    fi
  done
fi

