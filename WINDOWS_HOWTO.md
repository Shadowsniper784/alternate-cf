# Windows build artifacts

## What was built

- `dist/warpalt-windows-amd64.exe` — GUI
- `dist/warpaltd-windows-amd64.exe` — privileged service binary

Both are `GOOS=windows GOARCH=amd64` with `CGO_ENABLED=0`.

## Why Windows does not need CGO here

The Windows builds are pure-Go for the parts that matter:

- the GUI is a Wails WebView2 app; the WebView2 bootstrapping is delivered by the Wails runtime and the WebView2 runtime on the target machine, not by a local C dependency
- the daemon talks to Wintun through the `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` + `golang.zx2c4.com/wireguard/tun` stack, which is the same pure-Go Win32 path WireGuard for Windows uses

So on this Linux host we can build both Windows binaries without a Windows toolchain or cross-C toolchain.

## What the Windows binaries need to actually run

### GUI

- Windows 10 or 11 with the **WebView2 runtime** installed
- WebView2 is already present on current Windows 10/11 desktops in practice; if you want to be strict, the bootstrap requirement is the Evergreen WebView2 runtime

### Daemon

- administrator rights to install and start the service
- the service installs itself as `warpaltd` and runs as LocalSystem
- the first install is:
  - `warpaltd-windows-amd64.exe -install-service` from an elevated prompt
- after that, the service owns the Wintun adapter, routes, and MASQUE session
- the GUI connects over `\\.\pipe\warpalt-control` as a normal user

## Cross-build caveats

- These are cross-builds from Linux. They are useful for shipping artifacts, but the Windows service path is not fully testable here.
- The Windows-specific code paths are in:
  - `internal/daemon/main_windows.go`
  - `internal/daemon/listen_windows.go`
  - `internal/daemon/state_windows.go`
  - `internal/netcfg/netcfg_windows.go`
  - `internal/routes/apply_windows.go`
  - `internal/control/dial_windows.go`
  - `internal/tun/tun_windows.go`
  - `internal/warp/tun_windows.go`

On this host the Windows side is verified by:
- clean build
- `go vet ./...`
- `go test ./...`
- the daemon cross-compiling with no CGO and producing a valid PE32+ console executable

That means the Windows artifact is real and coherent; the one piece that still needs a Windows machine is the live service install + pipe + Wintun bootstrap.

## Rebuild command

From this host:

```bash
nix-shell -p webkitgtk_4_1 gtk3 pkg-config go_1_27 --run ./build.sh
```

That produces all four artifacts in `dist/`:

- `warpalt-linux-amd64`
- `warpaltd-linux-amd64`
- `warpalt-windows-amd64.exe`
- `warpaltd-windows-amd64.exe`
