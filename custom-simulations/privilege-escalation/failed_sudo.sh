#!/usr/bin/env bash
# Runs sudo non-interactively as a user without sudo rights -> "failed attempt to run sudo" log lines.
# Run this on a target as an UNPRIVILEGED lab user. Exit code is non-zero by design.
for i in 1 2 3; do sudo -n -k true 2>/dev/null || true; sleep 1; done
echo "failed sudo attempts generated"
