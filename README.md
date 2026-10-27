# warpalt

A third-party, cross-platform **Cloudflare One (WARP) client** with its own
native UI for **Windows** and **Linux**, written in **Go**.

warpalt is a *full alternative client*, not a wrapper: it speaks the WARP
MASQUE (Connect-IP, RFC 9484) protocol directly, manages its own TUN device
and implements split tunneling itself.

## What it does

- **Enable / disable** the tunnel with one button (real connect/disconnect,
  not a cosmetic switch).
- **Enroll with any organization subdomain** — enter your team name
  (`mycompany` for `mycompany.cloudflareaccess.com`), warpalt opens the
  sign-in page in your browser, you paste the token from the success screen.
- **Split tunnel that respects your organization's remote settings**: the
  device profile pushed by your Zero Trust admin (include/exclude mode and
  the route list) is fetched at connect time and applied as the base
  configuration. Organization entries are shown read-only in the UI.
- **Local additions on top**: routes you add (e.g. `10.0.3.1` for SSH to an
  internal host) are layered *on top of* organization policy. They are more
  specific, so they win for exactly those addresses — nothing your
  organization configured is ever removed. Overlaps are highlighted as
  conflicts in the UI.
- **SSH-friendly routing**: exclude mode uses two `/1` routes to divert the
  default space through the tunnel, so your machine's own default route is
  never deleted and everything reverts cleanly on disconnect. The MASQUE
  endpoint always bypasses its own tunnel.

## How it works

| Layer | Implementation |
|---|---|
| Registration / key enrollment | [usque](https://github.com/Diniboy1123/usque) `api` package (MIT) — the same public registration endpoint the official Android client uses, with your team JWT |
| Tunnel | MASQUE / Connect-IP via usque's `api.ConnectTunnel` in `warpaltd`, with a context-aware reconnect supervisor |
| TUN device | `wireguard-go/tun` in `warpaltd` (`/dev/net/tun` on Linux, Wintun on Windows) with the WARP-assigned addresses, MTU 1280 |
| Privileged service | `warpaltd`: owns the TUN device, routes and dataplane. Root systemd unit on Linux with only `CAP_NET_ADMIN`; LocalSystem Windows service on Windows |
| GUI ↔ daemon | `net/rpc/jsonrpc` over `/run/warpalt/control.sock` (Linux) or a named pipe (Windows). The GUI runs at normal user rights |
| Split tunnel | `internal/routes`: pure plan computation + platform appliers — `vishvananda/netlink` on Linux, WireGuard's `winipcfg` on Windows |
| Remote policy | `GET https://api.cloudflareclient.com/v0a4471/reg/<device>` with the device bearer token; the `policy` block (include/exclude/service_mode) is parsed tolerantly (top-level or under `result`) |
| UI | [Wails v2](https://wails.io) main window (HTML/CSS/JS frontend, Go backend) |

## Privilege model

The GUI never runs elevated. `warpalt` (Wails/WebView/WebKit) runs at normal
user rights and talks to `warpaltd`, which owns only the kernel-facing pieces:
the TUN device, its addresses/MTU, the route table and the packet engine.

- **Linux:** `warpaltd` is a systemd **system** unit running as root with only
  `CAP_NET_ADMIN` in its bounding/ambient set, `NoNewPrivileges=yes` and the
  sandbox options from [`packaging/warpaltd.service`](packaging/warpaltd.service).
  It creates `/run/warpalt/control.sock` (0660, `root:warpalt`). Add the desktop
  user to the `warpalt` group once.
- **Windows:** a non-admin process cannot open a Wintun adapter at all, so
  `warpaltd.exe` is a service running as LocalSystem. It creates a named pipe
  whose DACL grants SYSTEM, Administrators and interactive users, and rejects
  non-interactive service accounts. The GUI stays `asInvoker`; there is no UAC
  prompt on launch.
- **No root GUI, no `setcap` on the GUI, no setuid binary.**

See [`docs/privilege-separation.md`](docs/privilege-separation.md) for the full
permission matrix, the source-verified Windows constraints and the reuse
catalogue.

## Building

### Windows

WebView2 is preinstalled on Windows 10/11. Build both binaries from a normal
(non-elevated) shell:

```bash
CGO_ENABLED=0 GOOS=windows go build -tags production -o warpalt.exe .
CGO_ENABLED=0 GOOS=windows go build -o warpaltd.exe ./cmd/warpaltd
```

Put **`wintun.dll`** (from [wintun.net](https://www.wintun.net)) next to
`warpaltd.exe`, then install the service once from an **elevated** prompt:

```powershell
.\warpaltd.exe -install-service
```

The GUI is started normally (no *Run as administrator*). Remove the service
with `warpaltd.exe -uninstall-service` from an elevated prompt.

### Linux

Wails uses WebKitGTK for its window, so install the dev package once:

```bash
sudo apt install libwebkit2gtk-4.1-dev      # Debian/Ubuntu
# Fedora: sudo dnf install webkit2gtk4.1-devel gtk3-devel
make build-app
make build-daemon
```

Install the daemon as a system service (packagers put the unit in
`/usr/lib/systemd/system/` and the binary in `/usr/bin/`):

```bash
sudo install -m 0644 packaging/warpaltd.service /etc/systemd/system/warpaltd.service
sudo install -m 0644 packaging/warpalt.sysusers /usr/lib/sysusers.d/warpalt.conf
sudo install -m 0755 dist/warpaltd /usr/bin/warpaltd
sudo systemd-sysusers
sudo usermod -aG warpalt "$USER"   # log out/in once
sudo systemctl daemon-reload
sudo systemctl enable --now warpaltd
```

Then run `./dist/warpalt` as yourself. The GUI refuses to start a tunnel if
the service is not running and says so in the UI.

### Tests

```bash
go test ./...
```

Or just `./build.sh` to produce both binaries in `dist/`.
(The `production` tag is mandatory — plain `go build` compiles but the app
exits at startup with a Wails build-tags error.)

### Verbose logging

Set `WARPALT_VERBOSE=1` on either process to log every step to **stdout**:
the GUI prints frontend (`[ui]`), control-plane (`[warpalt]`) and startup
lines; the daemon prints `[warpaltd]` lines for startup, the listening
endpoint and every accepted control client (`./warpaltd -v` does the same).

```bash
WARPALT_VERBOSE=1 ./dist/warpalt                 # GUI, logs to stdout
sudo -E env WARPALT_VERBOSE=1 ./dist/warpaltd -v # daemon, logs to stdout
```

If the window stays on "Loading warpalt…", the splash now gives up after six
seconds and says so; the verbose log shows which call never returned and why
(missing service, wrong socket path, permission denied on the socket).

## Using it

1. **Enroll**: type your team subdomain, click *Open sign-in page*, complete
   authentication in the browser, then paste the token (or the whole
   `com.cloudflare.warp://…` link) from the success screen. Accept the
   Cloudflare ToS checkbox — registration is refused without it.
2. **Enable** with the big button. warpalt fetches your organization's device
   profile, applies it, and brings the MASQUE tunnel up.
3. **Split tunnel** tab: your organization's mode and entries on top (read
   only), your local additions below (editable). E.g. add `10.0.3.1/32` to
   reach an internal host over SSH; conflicts with organization entries are
   flagged.
4. **Device** tab: registration details, refresh of organization settings,
   log out (deletes the local registration).

## Limitations (honest list)

- **DNS is not touched.** Your system resolver keeps working. If your
  organization relies on Gateway DNS (DoH to Gateway) for internal names,
  internal hostnames won't resolve — use IPs for split-tunnel entries for
  now. A DNS proxy is the documented next step, not part of this change.
- **No kill switch yet.** The daemon removes its routes when the session is
  stopped or fails, but it does not install a firewall block during the
  transition. The nftables/WFP work is scoped in the privilege document.
- **Linux and Windows are the supported targets.** The code still builds for
  darwin so the GUI can be developed there, but `warpaltd` returns a clear
  "no TUN backend" error on macOS.
- **Remote policy retrieval is reverse-engineered.** Cloudflare does not
  document a client-facing API for the device profile; community clients use
  the registration read (`GET /v0a4471/reg/<id>`). If Cloudflare changes it,
  warpalt degrades gracefully: it falls back to your chosen local mode plus
  Cloudflare's recommended default exclusions (RFC1918 etc.) and says so in
  the UI.
- **Hostname entries are resolved at connect time** (not continuously
  re-resolved).
- **Terms of Service**: this project registers devices through Cloudflare's
  public registration API the way community clients (usque, wgcf) do. You
  are responsible for complying with the
  [Cloudflare One Agent Terms](https://www.cloudflare.com/cloudflareone/application/terms/)
  and your organization's policies.

## Research background

This project started from a survey of the ecosystem (Oct 2026):

- Existing third-party UIs (PyWarp, warp-cli-gui, warp-gui-app, …) all wrap
  the official client's `warp-cli`; there was no standalone client with a
  native UI.
- Protocol-level building blocks: [usque](https://github.com/Diniboy1123/usque)
  (MASQUE, Go, Zero Trust token support), [wgcf](https://github.com/ViRb3/wgcf)
  (consumer WireGuard configs only), `warp-wireguard-gen` (Rust). None of
  them manage split-tunnel routes — that part is implemented here.
- The official client's split-tunnel semantics (include/exclude modes,
  profile-driven, client edits the OS route table + firewall) are documented
  in [Cloudflare's client architecture docs](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/client-architecture/);
  the remote-profile endpoint used here is community reverse engineering
  (wgcf's OpenAPI spec and WarpClient's research notes).

## Project layout

```
main.go                     Wails entrypoint
frontend/                   HTML/CSS/JS UI
cmd/warpaltd/               Privileged service entry point
internal/app/               Bound GUI API (status, split view, enroll, toggle)
internal/control/           Unprivileged JSON-RPC client for warpaltd
internal/protocol/          Shared GUI ↔ daemon wire contract
internal/daemon/            Lifecycle, control socket/pipe, route/plan updates
internal/engine/            MASQUE session supervisor (runs as the daemon)
internal/netcfg/            TUN creation/addresses/MTU (linux/windows/unsupported)
internal/warp/              Identity, enrollment, remote policy, keys
internal/routes/            Split-tunnel plan + linux/windows route appliers
internal/settings/          Local settings (fallback mode, local additions)
packaging/warpaltd.service  Hardened Linux systemd unit
```
