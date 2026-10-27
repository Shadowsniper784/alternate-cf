#!/usr/bin/env bash
# Production build: GUI and daemon via the Nix flake.
# Usage: ./scripts/prod.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== warpalt Production Build ==="
nix build .#warpalt .#warpaltd 2>&1 | tail -10

echo ""
echo "=== Build Complete ==="
echo "GUI:    ./result/bin/warpalt  (run as your normal user)"
echo "Daemon: install packaging/warpaltd.service and ./result/bin/warpaltd"
echo "        see README.md for the systemd/Windows service setup"
