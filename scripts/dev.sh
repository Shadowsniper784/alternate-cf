#!/usr/bin/env bash
# Development script: starts wails dev -browser with correct build tags.
# Usage: ./scripts/dev.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== warpalt Development Mode ==="
echo "The GUI runs unprivileged in your browser at http://localhost:34115"
echo "For tunnel operations, run warpaltd separately (systemd or WARPALT_SOCKET)."
echo ""

nix develop --extra-experimental-features 'nix-command' \
  --command bash -c '
    wails dev -browser -tags "webkit2_41"
  '
