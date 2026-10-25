#!/usr/bin/env bash
# Build warpalt for Linux and Windows into dist/.
#
# - "production" is required by Wails v2 (without it the app exits with
#   "Wails applications will not build without the correct build tags").
# - "webkit2_41" selects webkit2gtk-4.1 (Ubuntu 24.04+/Fedora 39+; drop it
#   and use webkit2gtk-4.0 on older distros).
# - Linux needs the WebKitGTK dev package installed:
#     sudo apt install libwebkit2gtk-4.1-dev
# - Windows builds need no cgo; WebView2 is preinstalled on Win10/11.
set -euo pipefail

mkdir -p dist

echo "==> linux/amd64"
go build -tags "production webkit2_41" -trimpath -o dist/warpalt-linux-amd64 .

echo "==> windows/amd64"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags production -trimpath -o dist/warpalt-windows-amd64.exe .

echo "==> done"
ls -la dist/
