#!/usr/bin/env bash
# Build warpalt (GUI) and warpaltd (privileged service) for Linux and Windows
# into dist/. Must be run inside a nix shell that has webkitgtk_4_1 + gtk3 +
# pkg-config + go_1_27 available.
#
# One-shot:  nix-shell -p webkitgtk_4_1 gtk3 pkg-config go_1_27 --run ./build.sh
#
# The script itself only needs bash + go in PATH; it does not require sudo.

set -euo pipefail

# The GUI needs pkg-config + webkitgtk to link. Outside the dev shell those
# are missing, so re-exec inside `nix develop` when it is available.
if ! command -v pkg-config >/dev/null 2>&1 && command -v nix >/dev/null 2>&1 && [ -f flake.nix ]; then
  echo "==> pkg-config not found; re-running inside nix develop"
  exec nix develop -c "$0" "$@"
fi

GO="${GO:-go}"
if ! command -v "$GO" >/dev/null 2>&1; then
  echo "error: go not found in PATH (wrap this script in nix-shell -p go_1_27)" >&2
  exit 1
fi

mkdir -p dist

echo "==> linux/amd64 gui"
"$GO" build -tags "production webkit2_41" -trimpath -o dist/warpalt-linux-amd64 .

echo "==> linux/amd64 daemon"
"$GO" build -trimpath -o dist/warpaltd-linux-amd64 ./cmd/warpaltd

echo "==> windows/amd64 gui"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO" build -tags production -trimpath -o dist/warpalt-windows-amd64.exe .

echo "==> windows/amd64 daemon"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO" build -trimpath -o dist/warpaltd-windows-amd64.exe ./cmd/warpaltd

echo "==> done"
ls -la dist/
