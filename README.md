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
| Tunnel | MASQUE / Connect-IP via usque's `api.ConnectTunnel` + our own session supervisor (accurate connect/reconnect/disconnect states for the UI) |
| TUN device | `songgao/water` (Linux TUN / Windows wintun) with the WARP-assigned addresses, MTU 1280 |
| Split tunnel | `internal/routes`: pure plan computation + platform appliers — `vishvananda/netlink` on Linux, WireGuard's `winipcfg` on Windows |
| Remote policy | `GET https://api.cloudflareclient.com/v0a4471/reg/<device>` with the device bearer token; the `policy` block (include/exclude/service_mode) is parsed tolerantly (top-level or under `result`) |
| UI | [Wails v2](https://wails.io) main window (HTML/CSS/JS frontend, Go backend) |

## Building

### Windows

WebView2 is preinstalled on Windows 10/11. From a normal Go toolchain:

```bash
CGO_ENABLED=0 go build -tags production -o warpalt.exe .
```

You also need **`wintun.dll`** (from [wintun.net](https://www.wintun.net))
next to the executable, and the app must be started **as Administrator**
(TUN + route changes require it).

### Linux

Wails uses WebKitGTK for its window, so install the dev package once:

```bash
sudo apt install libwebkit2gtk-4.1-dev      # Debian/Ubuntu
# Fedora: sudo dnf install webkit2gtk4.1-devel gtk3-devel
go build -tags "production webkit2_41" -o warpalt .
```

Running the tunnel requires **root** (CAP_NET_ADMIN for the TUN device and
route changes):

```bash
sudo ./warpalt
```

### Tests

```bash
go test ./...
```

Or just `./build.sh` to produce both binaries in `dist/`.
(The `production` tag is mandatory — plain `go build` compiles but the app
exits at startup with a Wails build-tags error.)

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
  now. (A local DNS proxy like the official client's is a natural next step.)
- **Remote policy retrieval is reverse-engineered.** Cloudflare does not
  document a client-facing API for the device profile; community clients use
  the registration read (`GET /v0a4471/reg/<id>`). If Cloudflare changes it,
  warpalt degrades gracefully: it falls back to your chosen local mode plus
  Cloudflare's recommended default exclusions (RFC1918 etc.) and says so in
  the UI.
- **Hostname entries are resolved at connect time** (not continuously
  re-resolved).
- **Linux and Windows only.**
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
internal/app/               Bound API (status, split view, enroll, toggle)
internal/warp/              Identity, enrollment, remote policy, MASQUE session, TUN
internal/routes/            Split-tunnel plan + linux/windows route appliers
internal/settings/          Local settings (fallback mode, local additions)
```
