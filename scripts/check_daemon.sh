#!/usr/bin/env bash
# Check the warpaltd service and the two build outputs.
# Usage: ./scripts/check_daemon.sh
set -euo pipefail

cd "$(dirname "$0")/.."

SERVICE=warpaltd
SOCKET=/run/warpalt/control.sock
ERRORS=0

echo "=== warpalt service check ==="

if [ -x dist/warpaltd ]; then
  echo "ok   dist/warpaltd exists"
else
  echo "warn dist/warpaltd missing; run 'make build-daemon'"
  ERRORS=$((ERRORS + 1))
fi

if [ -x dist/warpalt ]; then
  echo "ok   dist/warpalt exists"
else
  echo "warn dist/warpalt missing; run 'make build-app'"
  ERRORS=$((ERRORS + 1))
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE"; then
    echo "ok   $SERVICE is active"
  else
    echo "warn $SERVICE is not active"
    echo "     install/enable it with packaging/warpaltd.service (see README)"
    ERRORS=$((ERRORS + 1))
  fi
fi

if [ -S "$SOCKET" ]; then
  echo "ok   control socket exists: $SOCKET"
  mode=$(stat -c '%a %U:%G' "$SOCKET" 2>/dev/null || true)
  echo "     $mode (expected 660 root:warpalt)"
else
  echo "warn control socket not found: $SOCKET"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$ERRORS check(s) need attention."
  exit 1
fi
