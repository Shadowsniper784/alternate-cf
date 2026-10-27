# Daemon diagnostics — final state

## What I verified

- **Daemon starts on a user socket**, no `CAP_NET_ADMIN` needed for the control plane itself:
  - `WARPALT_SOCKET=/tmp/warpalt-sock-dir/control.sock ./dist/warpaltd-linux-amd64`
- **JSON-RPC surface works**:
  - `Warpalt.Ping` → `{"version":1}`
  - `Warpalt.Status` → `{"state":"disconnected","enrolled":false}`
- **Failure path is clean**, not a panic:
  - `Warpalt.Connect` without real TUN capability returns the expected `operation not permitted` / `CAP_NET_ADMIN` message
- **Rebuilt + stripped binaries**:
  - `dist/warpaltd-linux-amd64`
  - `dist/warpalt-linux-amd64`
  - `dist/warpaltd-windows-amd64.exe`
  - `dist/warpalt-windows-amd64.exe`
- **`go vet ./...`** — clean
- **`go test -count=1 -short -timeout=90s -race ./internal/...`** — passed

## The actual blocker on this host

The only stderr problem that was real was the GTK theme file:

- `~/.config/gtk-3.0/noctalia.css` was importing itself: `@import url("noctalia.css");`
- That produced the recursive parse warning you saw in the GUI's stderr
- I broke the loop by pointing that import at a minimal override file instead

After that, the GUI's stderr only contains the harmless JSC signal note.

## What "not enrolled, stuck on loading warpalt" means here

Once the daemon is reachable:

- The backend is not blank — the daemon answers `Status` correctly
- "not enrolled" is the right pre-enrollment state
- The old "blank window" path in `frontend/app.js` was already changed so it no longer hides both views forever; it now shows a loading overlay and an explicit banner when the backend is absent

So on this host the app is no longer silently blank at boot. What I still could not finish end-to-end on this machine is driving the GUI's own webview long enough to confirm the rendered enrollment screen here — the daemon and the control plane are verified; the GUI rendering path on this specific Hyprland session from a plain shell launch is the part that still needs a real compositor-attached launch to confirm.

## One-liner that works

```bash
nix-shell -p webkitgtk_4_1 gtk3 pkg-config go_1_27 --run ./build.sh
```

Dev run:

```bash
WARPALT_SOCKET=/tmp/warpalt-sock-dir/control.sock ./dist/warpaltd-linux-amd64
```

and the GUI with the same `WARPALT_SOCKET`.

## Windows equivalent

- GUI: `warpalt-windows-amd64.exe` (WebView2 already on Win10/11)
- Daemon: `warpaltd-windows-amd64.exe -install-service` once elevated, then it owns Wintun + `\\.\pipe\warpalt-control`
- GUI needs no admin rights

## Files that already changed

Already-modified project files from earlier turns:

- `frontend/app.js`
- `frontend/index.html`
- `frontend/style.css`
- `build.sh`
- `flake.nix`
- `default.nix`
- `go.mod`
- `go.sum`
- `internal/app/app.go`
- `internal/app/app_test.go`
- `internal/routes/apply_linux.go`
- `internal/routes/apply_windows.go`
- `internal/routes/plan.go`
- `internal/warp/identity.go`
- `internal/warp/profile.go`
- `internal/warp/tun_linux.go`
- `internal/warp/tun_windows.go`
- `internal/warp/tun_unsupported.go`
- `internal/warp/tunnel.go`
- `internal/warp/warp_test.go`

Host-level change this turn:

- `~/.config/gtk-3.0/noctalia.css` — self-import redirected to `noctalia-recurse-override.css`
- `~/.config/gtk-3.0/noctalia-recurse-override.css` — new minimal override that stops the recursion

## If you want the remaining gap closed

The cleanest next step is to launch the GUI attached to your real Hyprland session (`WAYLAND_DISPLAY=wayland-1` + your DBus session bus), then check the window content and the JS console path. That is what turns "daemon verified, UI not blank anymore" into "GUI works on this machine".
