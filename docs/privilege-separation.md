# Privileges, userland and daemons

**Status:** research + decision record · October 2026
**Scope:** Linux (systemd, x86_64) and Windows 10/11 (x86_64). macOS is out of scope; the
`darwin` stubs in the tree are not a supported target.
**Question answered:** the whole app cannot run as root/Administrator. Which local
permissions does warpalt actually need, which of them can live in userland, what must live in
a privileged daemon, and which existing components can we reuse instead of writing a daemon.

## Implementation status

The core split is implemented in this tree:

- `warpalt` (Wails) is unprivileged and has no TUN/netlink/winipcfg imports. It talks to the
daemon through `internal/control`.
- `warpaltd` owns the TUN device, addresses/MTU, route table and MASQUE engine
  (`internal/daemon`, `internal/netcfg`, `internal/engine`).
- Linux: `packaging/warpaltd.service` runs it as a hardened systemd system unit with only
  `CAP_NET_ADMIN`; the socket is `/run/warpalt/control.sock` (0660, `root:warpalt`) with
  `SO_PEERCRED` defence in depth.
- Windows: `warpaltd.exe -install-service` installs a LocalSystem service; the control channel
  is a named pipe with an explicit DACL and a client-token check.
- The route plan is computed in the GUI (policy fetch, DNS resolution, conflict detection) and
  sent to the daemon as data; the daemon never resolves names or fetches policy.

**Not implemented yet:** DNS takeover/restore, the nftables/WFP kill switch, and the
zero-privilege SOCKS/HTTP proxy mode. They are scoped below as Phase 3/4 work, not implied by
the daemon split.

---

## 0. Decisions at a glance

| Decision | Choice |
|---|---|
| GUI privilege | **None.** `asInvoker` on Windows, ordinary desktop uid on Linux. |
| Privileged component | A **separate binary**, `warpaltd` (same name both platforms). The Wails/WebKit/WebView process never holds a privileged handle. |
| Linux host for `warpaltd` | systemd **system** service; root UID with a bounded capability set and a sandboxed unit. |
| Windows host for `warpaltd` | Windows **service** running as `LocalSystem`, installed once (MSI or a one-time UAC prompt). |
| IPC | `net/rpc/jsonrpc` over a `net.Conn`: Unix socket on Linux, named pipe on Windows. No custom framing. |
| IPC authorization | Linux: `SO_PEERCRED` + Unix-socket mode/group. Windows: explicit pipe SDDL + client PID → process token user check. |
| TUN | [wireguard-go `tun`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun) on both platforms (`CreateTUN`, `CreateTUNFromFile`, `Device.File()`), which wraps Wintun on Windows. Replaces `songgao/water` and the hand-rolled TUN code. |
| Linux dataplane | Phase 1: inside `warpaltd` (root). Phase 2 optional: hand the TUN fd to an unprivileged worker (the OpenVPN 3 pattern). |
| Windows dataplane | **Must** be inside the service. A non-admin process cannot open a Wintun adapter at all; there is no fd/handle handoff. |
| Protocol / enrollment | Reuse [usque](https://github.com/Diniboy1123/usque) `api` (already vendored). |
| Linux routes / Windows routes | `vishvananda/netlink` / `winipcfg`. |
| Linux firewall / Windows firewall | nftables (`google/nftables`) / WFP (`wireguard-windows/tunnel/firewall`, MIT). |
| DNS | Linux: systemd-resolved D-Bus or `/etc/resolv.conf` with backup. Windows: `winipcfg.SetDNS` on adapters. |
| Zero-privilege mode | Userspace netstack + local SOCKS5/HTTP proxy (usque's `socks` / `http-proxy` model). Per-app, not system-wide. The **only** option on Windows without admin. |

The rest of this document explains why, with the primary sources.

---

## 1. What "permissions" means here

Two different things are often mixed up:

1. **Cloudflare-side authorization.** Enrollment is governed by the Access enrollment rule
   (an Access application of type `warp`); the device profile then controls split tunnel,
   DNS behaviour and connection mode. A device needs no Cloudflare API token; a headless
   device uses a service token instead of an interactive login. Nothing in this document
   changes that, and none of it requires local administrator rights.
2. **Operating-system privileges.** These are the TUN device, addresses, routes, resolver
   settings and firewall. They are what force a privileged component.

This document is about (2).

### Why the GUI cannot be the privileged component

- On Linux, Wails renders with WebKitGTK. Running a browser engine as root is a bad idea on
  its own: it parses network content and is the largest attack surface in the application.
  A root GUI also has to reach the user's Wayland/X11 session and D-Bus session bus, which is
  awkward and often requires environment surgery (`XAUTHORITY`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS`). `sudo ./warpalt` additionally leaks root-owned files into
  `$HOME` and makes the running app unkillable by the desktop session.
- On Windows the equivalent is worse: an app manifest with
  `requestedExecutionLevel level="requireAdministrator"` produces a UAC prompt on **every**
  launch, the elevated process cannot easily talk to the user's desktop, drag-and-drop from
  Explorer breaks (UIPI), and WebView2 runs with a high-integrity token.
- The privilege is also much larger than "make a tunnel": `CAP_NET_ADMIN` on Linux can
  change any interface, any route, any firewall rule on the host; on Windows an elevated
  process can do anything. The smaller the process holding it, the better.

Cloudflare's own client is built this way. Their architecture page says the desktop client
"consists of two components: a service/daemon that handles all client functionality on your
device, and a GUI wrapper that makes it easier for a user to interact with the daemon."
([Client architecture](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/client-architecture/))

---

## 2. What actually needs privilege

`warpalt`'s tunnel is MASQUE / Connect-IP over QUIC. That entire path — TLS, HTTP/3, Connect-IP,
keepalives, reconnects, enrollment, device-profile fetch, the UI — needs **no** local privilege.
It is an outbound UDP socket to Cloudflare. Only the kernel-facing pieces do.

### 2.1 Operation matrix

| Operation | Linux requirement | Windows requirement | Notes |
|---|---|---|---|
| Open/create a TUN device | `CAP_NET_ADMIN` in the target netns | Administrators / SYSTEM | Kernel TUN/TAP docs: `CAP_NET_ADMIN` is required to create a device or attach to one you do not own. |
| Create a Wintun adapter | — | Administrators / SYSTEM | Driver install + device creation; see §5.1 for the driver ACL. |
| Set addresses, MTU, link up | `CAP_NET_ADMIN` | Administrators | Netlink / `winipcfg`. |
| Add/remove routes | `CAP_NET_ADMIN` | Administrators | Netlink / `winipcfg`. |
| Set system DNS | root (resolver file) or privileged D-Bus call | Administrators | §4.6 / §5.8. |
| Firewall / kill switch | `CAP_NET_ADMIN` (nftables) | Administrators (WFP) | Optional for include-mode, mandatory for a fail-closed exclude-mode. |
| Bind `127.0.2.2:53` DNS proxy | `CAP_NET_BIND_SERVICE` | Administrators (service) | Port 53 is privileged. `127.0.0.0/8` is local, so no address needs to be added on Linux. |
| `SO_BINDTODEVICE` / `SO_MARK` (endpoint bypass) | `CAP_NET_RAW` (`SO_BINDTODEVICE`), `CAP_NET_ADMIN` (`SO_MARK`) | n/a | Prefer a host route for the endpoint instead; it is what the current route plan already does. |
| MASQUE/QUIC, enrollment, policy fetch, UI | none | none | Outbound UDP/TCP + user files only. |
| Read/write the user's settings | user | user | Keep user settings in the user profile; keep service state in the system state dir. |

### 2.2 The important consequence

The privileged daemon does **not** need the user's browser, the UI, the policy parser, or any
untrusted rendering. It needs a small, fixed set of network-configuration verbs and the tunnel
dataplane. That is why it can be a separate, small, auditable binary.

---

## 3. Where the repository is today

This matters because it is tempting to extend the existing `internal/warpdaemon` — that would be
the wrong move.

- `internal/app/app.go` constructs `warp.New(...)` and the tunnel in the GUI process. That is the
  code path that currently forces `sudo ./warpalt`. It also uses `wails.Window` /
  `wails.CurrentWindow()`, which do not exist in Wails v2 (they are v3-style), so the app package
  does not compile.
- `internal/warpdaemon` already sketched a daemon + socket split:
  - Linux: `/var/run/warpalt/warpalt.sock`, `chmod 0660`, **no peer-credential check**. Any local
    user who can open the socket can drive a root daemon.
  - Commands are decoded into `map[string]any` and the whole map is logged
    (`handleStart` prints `cfgJSON`), which would log keys/tokens.
  - The Windows listener is a placeholder: `namedPipeConn.Read()` returns
    `windows.ERROR_NOT_FOUND`, and `SetOnConnect` never blocks on `ConnectNamedPipe`. Nothing
    works there yet.
  - `tunnel.StartTunnel` accepts an arbitrary identity from the client and has no validation or
    authorization.
- `internal/tun` is dead weight and broken: `tun.go` is `//go:build !linux`, so on Linux
  `Identity`/`Interface` are undefined (`internal/tun/tun_linux.go:19`). `internal/tun/tun_windows.go`
  is a stub. It duplicates `internal/warp/tun_linux.go` / `tun_windows.go`.
- `internal/tunnel` is a second, parallel platform dispatch (`TunnelHandle`, `tunnel_linux.go`,
  `tunnel_windows.go`, `darwin` stubs, `example.go`) that is partly unused. The handover document
  already flags it as redundant.
- `internal/settings` calls `warp.Dir()`, which does not exist.
- Baseline check in this workspace (`go build ./internal/...`, Go 1.27.3, vendored deps):

  ```
  internal/tun/tun_linux.go:19:16: undefined: Identity
  internal/tun/tun_linux.go:19:27: undefined: Interface
  internal/settings/settings.go:27:19: undefined: warp.Dir
  internal/app/app.go:14:18: undefined: wails.Window
  internal/app/app.go:30:19: undefined: wails.CurrentWindow
  internal/app/app.go:31:46: undefined: events
  ```

**Verdict:** do not extend this daemon. Keep the *idea* (separate binary, socket, state broadcast),
throw away the implementation, and delete `internal/tun` and `internal/tunnel` rather than fixing
them. The new daemon should be built around reused libraries (§7), not around this scaffolding.

---

## 4. Linux

### 4.1 Options considered

| Mechanism | Verdict | Why |
|---|---|---|
| Run the whole app as root / `sudo` | **Rejected** | Browser engine as root, session integration, root-owned user files, large attack surface. This is the problem statement. |
| `setuid` helper | **Rejected** | Full root, not just netadmin; Go + setuid is fragile; no capability bounding. |
| `setcap cap_net_admin+ep` on the GUI | **Rejected** | The GUI parses untrusted content; `CAP_NET_ADMIN` is effectively network-root (routes, firewall, any interface). Desktop shortcuts would also silently launch a privileged process. |
| File capabilities on a small helper | **Not sufficient alone** | `CAP_NET_ADMIN` covers TUN/routes/nftables, but not writing `/etc/resolv.conf` (needs DAC/root) and not binding port 53 (needs `CAP_NET_BIND_SERVICE`). It can be combined with a resolver D-Bus call, but then the helper needs a polkit rule too. Also impossible to apply in place to Nix store paths. Keep as a fallback for a "portable tarball" install, not as the primary design. |
| **systemd system service** | **Recommended** | This is what `warp-svc`, `mullvad-daemon` and `tailscaled` do. Auto-start at boot, auto-restart, journald logging, `RuntimeDirectory`/`StateDirectory`, and the whole systemd sandbox is available. |
| D-Bus service activation + polkit | Viable alternative | The OpenVPN 3 model: no always-running root process, daemon starts on demand, per-user authorization through the system bus. More moving parts (D-Bus policy, service files, polkit rules) and more failure modes. Pick this only if "no persistent root daemon" is a hard requirement. |
| Persistent TUN owned by the user | Partial | `ip tuntap add dev warp0 mode tun user $USER` lets an unprivileged process attach to an existing device (kernel docs). But creating the device, assigning addresses/MTU and changing routes still needs privilege, and an unmanaged persistent device is a leftover. Good for a boot-time `systemd-networkd` setup, not for policy-driven split tunneling. |
| Unprivileged user namespaces | Niche | `unshare -Urn` gives `CAP_NET_ADMIN` inside the new netns, so an unprivileged user can create a TUN **inside that namespace** (verified locally, see §10). But processes outside the namespace do not use it. Useful for "run this app inside the VPN namespace" and for rootless containers, not for a system-wide VPN. Some distros restrict unprivileged userns. |
| Userspace netstack + SOCKS/HTTP proxy | Supported as a mode | No TUN, no routes, no DNS changes, no privilege at all. Only applications configured to use the proxy are tunneled. This is the zero-install mode (§8). |

### 4.2 What existing clients do (and what to copy)

| Client | Privileged part | Unprivileged part | Lesson |
|---|---|---|---|
| Cloudflare One Client (Linux) | `warp-svc` systemd service | `warp-cli`, GUI | Service + wrapper split; the service owns TUN, routes, firewall, local DNS proxy. Cloudflare's docs show `/etc/resolv.conf` rewritten to `127.0.2.2/3` with a `# This file was generated by cloudflare-warp` header. |
| Mullvad | `mullvad-daemon` as root | Electron GUI over UDS | Explicitly: "the app is split into two parts: unprivileged frontends ... a privileged system service." Their security doc says the local management interface is reachable by any local process and that protecting against that is **outside the threat model**. They use nftables on Linux and WFP on Windows, and fail closed while connected, connecting or in error. |
| OpenVPN 3 Linux | `openvpn3-service-netcfg` as root | session manager + per-tunnel backend clients as `openvpn` user | The netcfg service opens the TUN and returns the **file descriptor over D-Bus** (`GetFD(..., "Establish")`); the process that speaks the VPN protocol runs unprivileged. This is the strongest precedent for a Linux fd handoff. |
| Tailscale | `tailscaled` (root by default) | `tailscale` CLI, GUI | Also ships `--tun=userspace-networking` for environments without TUN/root, exposing SOCKS5/HTTP. Same two-mode shape we want. |

### 4.3 Recommended Linux architecture

```
┌──────────────────────────────┐         ┌──────────────────────────────────────┐
│ warpalt (Wails, user uid)    │         │ warpaltd (systemd, root, sandboxed)  │
│                              │  UDS    │                                      │
│ UI, enrollment, policy fetch │◄───────►│ TUN create/own, addr, MTU, up        │
│ status display               │ JSON-RPC│ routes + rollback, endpoint bypass   │
│ optional userspace proxy     │         │ DNS set/restore, nftables            │
│                              │         │ MASQUE engine (phase 1)              │
└──────────────────────────────┘         └──────────────────────────────────────┘
```

`warpaltd` is a separate Go binary with **no Wails dependency**. Build it with the same module so
the shared `internal/protocol` types cannot drift.

### 4.4 systemd unit

```ini
# /usr/lib/systemd/system/warpaltd.service
[Unit]
Description=warpalt tunnel service
Documentation=man:warpaltd(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/libexec/warpaltd
Restart=on-failure
RestartSec=2s

# The group that may open the control socket. With Group= set, systemd also
# creates RuntimeDirectory/StateDirectory as root:warpalt, so 0750 lets the
# desktop user traverse /run/warpalt to reach the 0660 socket.
Group=warpalt
RuntimeDirectory=warpalt
RuntimeDirectoryMode=0750
StateDirectory=warpalt
StateDirectoryMode=0750

# The daemon needs netadmin + the ability to bind :53. Nothing else.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
# Add CAP_NET_RAW only if you use SO_BINDTODEVICE.

# Sandbox. ProtectSystem=yes keeps /usr and /boot read-only but leaves /etc
# writable, which the resolv.conf fallback needs. Use ProtectSystem=strict with
# ReadWritePaths=... if you only ever use systemd-resolved.
PrivateTmp=yes
PrivateDevices=no
ProtectHome=yes
ProtectSystem=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

Notes:

- `Type=notify` requires `sd_notify` (e.g. `github.com/coreos/go-systemd/v22/daemon`); use
  `Type=simple` if you do not want that dependency.
- UID 0 is retained because the resolver-file fallback needs DAC access. The capability bounding
  set still prevents the daemon from loading modules, changing the clock, tracing processes, etc.
  If you want to avoid root entirely, run as a dedicated `warpalt` user with the two ambient
  capabilities and make DNS exclusively a systemd-resolved D-Bus call plus a polkit rule; that is
  the "no root daemon" variant, at the cost of a distro-specific polkit file.
- `RestrictAddressFamilies` deliberately includes `AF_NETLINK` (routes) and excludes `AF_PACKET`
  (no raw sniffing).
- Run `systemd-analyze security warpaltd.service` in CI and keep the exposure score honest.

### 4.5 Socket, IPC and authorization

- Path: `/run/warpalt/control.sock` (via `RuntimeDirectory=warpalt`).
- Owner/mode: `root:warpalt`, `0660`. Create the `warpalt` group at install time and add the
  desktop user. If the unit does not set `Group=warpalt`, the runtime directory is `root:root`,
  so either set it (as above) or `chown` the socket and directory in the daemon after `Listen`.
  If you prefer not to create a group, `0666` plus a peer-UID check also works, but the group
  makes the policy visible in `ls -l`.
- Authorization: after `Accept`, call `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)` on the
  raw fd and reject UIDs that are not root/the installing user. This is the Linux analogue of the
  Windows pipe ACL. It has been verified on this host (§10).
- Never listen on TCP. A TCP control socket would be reachable by websites through DNS rebinding
  and by other machines.
- Protocol: `net/rpc/jsonrpc` over the accepted `net.Conn`. It is in the standard library, it works
  identically over the Unix socket and the Windows named pipe, and it avoids inventing a framing
  format. Wrap the connection in a message-size limiter (see §6.3).

### 4.6 TUN, routes and DNS

**TUN.** Use `golang.zx2c4.com/wireguard/tun`:

```go
dev, err := tun.CreateTUN("warp0", 1280) // non-persistent
if err != nil { /* EPERM means no CAP_NET_ADMIN */ }
name, _ := dev.Name()                     // e.g. "warp0"
// configure addresses/MTU/link via netlink, then read/write dev
```

This replaces `songgao/water` and the duplicated `internal/warp/tun_linux.go` /
`internal/tun/tun_linux.go`. It also gives us `dev.File()` for the optional fd handoff, and the
same package works on Windows (wrapping Wintun), which keeps one code path for packet I/O.

**Cleanup is mostly free.** The kernel TUN docs: "When the program closes the file descriptor, the
network device and all corresponding routes will disappear." Create the device non-persistently,
keep the fd in the daemon, and a crash cannot leave a stale interface or routes behind. DNS is the
exception and needs an explicit backup/restore (§4.7).

**Routes.** `vishvananda/netlink`, following the plan already in `internal/routes`:

1. Snapshot the current default route (gateway + link index) before touching anything.
2. Add endpoint-bypass host routes for the MASQUE endpoint via the original gateway.
3. Add two `/1` routes (`0.0.0.0/1`, `128.0.0.0/1`) for exclude mode so the original default
   route is never deleted; add the org/local include list for include mode.
4. Keep a handle listing every route installed and remove them in reverse order on stop or on a
   partial failure (the existing `Handle` shape is right).
5. Re-read the default route on network change and on reconnect; do not cache it across link
   changes.

**DNS.** There are three backends in the wild and the daemon should detect, not assume:

| Backend | Preferred action |
|---|---|
| `systemd-resolved` present (`/run/systemd/resolve/` or `resolvectl` works) | Set DNS on the default link via the `org.freedesktop.resolve1.Manager` D-Bus API (`SetLinkDNS`, `SetLinkDNSEx`, `SetLinkDomains` with `~.`), or shell out to `resolvectl`. Save the previous per-link config for restore. |
| NetworkManager + no resolved | Set DNS on the active connection via `org.freedesktop.NetworkManager` (more moving parts), or fall back to the resolver file. |
| Neither | Write `/etc/resolv.conf` (following symlinks carefully), keeping a copy of the original bytes and a marker file; restore on disconnect and on next start if the marker is present. |

The official client takes the last route: it writes a generated `resolv.conf`. That is simple and
predictable, but it is also why VPN clients fight each other. Implement resolved first, file as the
fallback, and log which backend was used. If the app also runs a local DNS proxy on
`127.0.2.2`/`127.0.2.3` (the Cloudflare layout), point the chosen backend at those addresses.

**Firewall.** Include-mode (private apps only) works with routes alone; a bypassing app can still
leak. Exclude-mode needs a firewall to be fail-closed. Use nftables via `github.com/google/nftables`
in a dedicated `inet warpalt` table. Two viable shapes:

- Mark-based (Mullvad-style): the daemon sets `SO_MARK` on its own tunnel socket; the ruleset allows
  marked packets out and drops everything else not going to the tunnel interface or the endpoint.
- Interface-based: allow the WARP interface and the endpoint, drop forwarded/other traffic.

Decide whether the ruleset is removed on a clean stop (leak-while-off is acceptable to the user) or
kept on crash (fail-closed). If kept, add a boot-time unit that applies a blocking ruleset before
`warpaltd` starts, as Mullvad does; and make sure uninstall removes it.

### 4.7 Crash consistency

- TUN and routes: vanish with the fd, no action needed.
- DNS: write `/var/lib/warpalt/dns-backup.json` (the original resolver state, backend name, and a
  timestamp) before changing anything. On daemon start, if the backup exists, restore it before
  accepting clients. This covers SIGKILL, power loss and package upgrades.
- Socket: remove a stale socket at startup, and only after acquiring an exclusive lock
  (`flock` on `/run/warpalt/lock`) so two daemons cannot race.
- Remove the nftables table on clean stop; on startup, reconcile any leftover table.

### 4.8 Packaging

- **deb/rpm:** ship `warpalt` (GUI) in the user-visible path, `warpaltd` in `/usr/libexec`, the unit
  in `/usr/lib/systemd/system`, and a sysusers/tmpfiles snippet for the `warpalt` group. Use
  `dh_installsystemd` / `%systemd_post` to enable and start it. Do not use `setcap`; the unit's
  ambient capabilities are declarative and survive upgrades.
- **NixOS / Nix:** the store is read-only, so `setcap` on a store path is not an option. Provide a
  NixOS module with `systemd.services.warpaltd` and the same `AmbientCapabilities` /
  `CapabilityBoundingSet` / sandbox options, plus `systemd.tmpfiles.rules` for the group and state
  dir. The existing flake only targets `x86_64-linux`; that is fine for a first cut.
- **Portable tarball:** a `setcap cap_net_admin,cap_net_bind_service+ep` helper is possible as a
  fallback, but the resolver file write still needs root, so document the reduced functionality
  (resolved-only DNS) or keep the tarball in userspace-proxy mode.

---

## 5. Windows

### 5.1 Why Windows has no unprivileged TUN option

Wintun is not a normal user-openable device. Two independent gates in the driver/DLL:

1. **Device ACL.** The TUN dispatch device is created with the binary security descriptor of
   `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NWNRNX;;;HI)` — owner `SYSTEM`, `FILE_ALL_ACCESS` only to
   `SYSTEM` and `Builtin Administrators` (see `driver/wintun.c`, `TunDispatchSecurityDescriptor`,
   and the `SeAccessCheck` in `TunDispatchDeviceControl`). Ring registration (`TUN_IOCTL_REGISTER_RINGS`)
   is access-checked against that descriptor.
2. **Private namespace.** The adapter namespace is created with a boundary descriptor containing
   either `WinLocalSystemSid` or `WinBuiltinAdministratorsSid` (`api/namespace.c`,
   `CreateWellKnownSid(...)`), and the DLL's security attributes grant full access only to
   `SYSTEM` and `Builtin Administrators` (`O:SY` when the caller is SYSTEM, otherwise `O:BA`, with
   `D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)`; `api/main.c`, `InitializeSecurityObjects`).

`WintunOpenAdapter` and `WintunStartSession` therefore fail for a standard user; and creating an
adapter also installs/loads the driver, which requires administrator rights. This is not a policy we
can opt out of. There is also no supported way to pass a Wintun session or ring handle to another
process: the session is an in-process object, unlike a Unix fd.

**Consequences:**

- The **service must own the Wintun adapter, the session, and the packet pump**. The unprivileged
  GUI cannot do the dataplane.
- The service therefore also holds the identity needed to bring the tunnel up. Store it at machine
  scope (DPAPI, §5.7), not in the user's profile.
- A "relay packets to the GUI over the pipe" design is possible in principle but adds a copy per
  packet and a lot of new code. It is not worth it; every Windows VPN (WireGuard, Mullvad,
  Cloudflare WARP) keeps the dataplane in the service.

### 5.2 What existing Windows clients do

- **WireGuard for Windows** uses a *manager service* (`WireGuardManager`, LocalSystem) plus one
  *tunnel service* per tunnel (`WireGuardTunnel$name`, LocalSystem). Configurations are stored as
  `.conf.dpapi` readable only by LocalSystem/Administrators. The GUI talks to the manager service;
  elevation is obtained with [`elevate.exe`](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)
  / `ShellExecute(runas)` only when needed. MSIs are the recommended enterprise install.
  (`wireguard-windows` has an "embeddable DLL service" for third-party apps, but it is WireGuard-only;
  it is not reusable for MASQUE.)
- **Mullvad** runs `mullvad-daemon` as a Windows service and exposes a named pipe to the Electron
  GUI; it uses WFP for the kill switch and explicitly accepts that any local process can control
  the VPN.
- **Cloudflare One Client** is a service + GUI wrapper on Windows too; the service creates the
  `CloudflareWARP` adapter and the local DNS proxy.

### 5.3 Recommended Windows architecture

```
┌──────────────────────────────┐         ┌────────────────────────────────────────┐
│ warpalt.exe (asInvoker)      │         │ warpaltd.exe (Windows service,         │
│                              │ named   │ LocalSystem, Automatic delayed)        │
│ UI, enrollment, policy fetch │◄───────►│ Wintun adapter + session + dataplane   │
│ status display               │  pipe   │ addresses/MTU/routes, DNS, WFP         │
│ optional userspace proxy     │         │ DPAPI-protected identity               │
└──────────────────────────────┘         └────────────────────────────────────────┘
```

- Separate binary. Do not put the service in `warpalt.exe`: it would drag Wails/WebView2 into a
  LocalSystem process, and the service must be able to start before any user logs in.
- GUI manifest: `asInvoker`. A Go binary without a manifest defaults to `asInvoker`; verify the
  manifest Wails embeds and do not request `requireAdministrator`.
- Service account: `LocalSystem` (Wintun's ACL requires SYSTEM or Administrators; `LocalService`
  is not enough).

### 5.4 One-time install (no UAC on normal launches)

Preferred: an MSI (WiX/Inno) whose install custom action creates the service. For a portable
zip/first-run flow, the GUI can elevate only the install step:

```go
// GUI side, standard user, fires UAC once.
err := windows.ShellExecute(0,
    windows.StringToUTF16Ptr("runas"),
    windows.StringToUTF16Ptr(`"`+exePath+`" --install-service`),
    nil, nil, windows.SW_SHOWNORMAL)
```

The elevated invocation does the service work and exits:

```go
// --install-service, elevated.
func installService(exe string) error {
    m, err := mgr.Connect()
    if err != nil { return err } // ERROR_ACCESS_DENIED if not elevated
    defer m.Disconnect()

    if s, err := m.OpenService(serviceName); err == nil {
        s.Close()
        return nil // already installed
    }
    s, err := m.CreateService(serviceName, exe, mgr.Config{
        DisplayName:      "warpalt tunnel service",
        Description:      "Owns the WARP adapter, routes, DNS and tunnel for warpalt.",
        StartType:        mgr.StartAutomatic,
        DelayedAutoStart: true,
        ErrorControl:     mgr.ErrorNormal,
    })
    if err != nil { return err }
    defer s.Close()

    _ = s.SetRecoveryActions([]mgr.RecoveryAction{
        {Type: mgr.ServiceRestart, Delay: 2 * time.Second},
        {Type: mgr.ServiceRestart, Delay: 5 * time.Second},
    }, 24*60*60)

    return s.Start()
}
```

Service host (same binary, no Wails imports):

```go
func main() {
    if isService, err := svc.IsWindowsService(); err == nil && isService {
        _ = svc.Run(serviceName, &handler{})
        return
    }
    switch flag.Arg(0) {
    case "--install-service":   // elevated; see above
    case "--uninstall-service": // stop, delete, remove state
    default:                    // console mode for development
    }
}
```

Uninstall: `service.Control(svc.Stop)`, `service.Delete()` (if it returns
`ERROR_SERVICE_MARKED_FOR_DELETE`, retry after a short delay), then remove
`%ProgramData%\warpalt` and the adapters.

### 5.5 Named pipe and client verification

Use [`github.com/Microsoft/go-winio`](https://github.com/microsoft/go-winio) — do not write
`CreateNamedPipe`/`ConnectNamedPipe` by hand. It already sets
`FILE_PIPE_REJECT_REMOTE_CLIENTS`, supports message/byte modes, and takes an SDDL string:

```go
const pipeSDDL = `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`

l, err := winio.ListenPipe(`\\.\pipe\warpalt-control`, &winio.PipeConfig{
    SecurityDescriptor: pipeSDDL,
    InputBufferSize:    64 << 10,
    OutputBufferSize:   64 << 10,
})
```

- `SY` = LocalSystem, `BA` = Builtin Administrators, `IU` = interactive users. `GRGW` is
  read/write data only — a client cannot create another pipe instance
  (`FILE_CREATE_PIPE_INSTANCE` is not granted), so it cannot squat the name.
- Tighter: replace `IU` with the logon SID of the active console session, so only the logged-in
  user can connect. The Microsoft named-pipe security docs recommend the logon SID to keep other
  terminal-services sessions out. Go-winio's `PipeConfig` accepts any SDDL, so this is a one-line
  change plus a `GetTokenInformation(TokenLogonSid)` call in the session tracker.
- Verify the client after `Accept`; do not rely on the ACL alone:

```go
h := windows.Handle(conn.(interface{ Fd() uintptr }).Fd()) // go-winio *win32Pipe promotes Fd()
var pid uint32
if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil { return err }

proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
if err != nil { return err }
defer proc.Close()

var tok windows.Token
if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil { return err }
defer tok.Close()

u, err := tok.GetTokenUser()
if err != nil { return err }
if !allowedUser(u.User.Sid) { return errUnauthorized }
```

`allowedUser` accepts the console-session user, Administrators, and SYSTEM (adjust for your
threat model). This avoids impersonation entirely and works regardless of the impersonation level
the client requested. Two notes: (a) there is a small PID-reuse race between
`GetNamedPipeClientProcessId` and `OpenProcess`; if that matters, use
`ImpersonateNamedPipeClient` + `OpenThreadToken` instead, with clients connecting through
`DialPipeAccessImpLevel(..., PipeImpLevelImpersonation)` (go-winio's defaults are anonymous, so
plain `DialPipe` is not impersonatable); (b) do not grant non-admin users SCM rights on the
service (no `sc sdset`); all control flows through the pipe, and service stop/start stays an
administrator action.

- Same caveat as Linux: any process running as the allowed user can control the VPN. That is the
  same model as Mullvad and is acceptable for a desktop VPN, but the pipe surface must be small
  and non-dangerous (no paths, no commands, no arbitrary file writes) because of it.

### 5.6 Wintun adapter, addresses, routes

```go
// Prefer the cross-platform wrapper; it calls WintunCreateAdapter internally.
dev, err := tun.CreateTUN("warpalt", 1280) // wintun.dll must sit next to warpaltd.exe
name, _ := dev.Name()
```

- Ship `wintun.dll` next to `warpaltd.exe` (architecture-matched). The Go wrapper loads it with
  `LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32)`, so the
  executable's directory is searched regardless of the service's working directory — but it must
  actually be there (or in `System32`); a `%PATH%` entry is not enough.
- Addresses/routes: `winipcfg` (`AddIPAddress`, `AddRoute`, `GetIPForwardTable2`, route-change
  notifications via `RouteChangeCallback`). The existing `internal/routes/apply_windows.go`
  already uses the right shape (LUID + prefix + next hop) and can be ported into the daemon.
- MTU: use `luid.IPInterface(family)` and set `MibIPInterfaceRow.NLMTU`, then `Set()`. This is
  the path wireguard-windows uses and needs no `netsh` subprocess. (`MibIfRow2` alone has no
  setter; the `IPInterface` row does.)
- Use the two `/1` routes, not a default-route replacement, for the same reasons as Linux.

### 5.7 State, secrets and ACLs

- `%ProgramData%\warpalt\`:
  - `identity.dpapi` — identity + enrollment material, encrypted with DPAPI **machine** scope
    (`windows.CryptProtectData(..., windows.CRYPTPROTECT_LOCAL_MACHINE, ...)`), ACL `SYSTEM` +
    `Administrators` only.
  - `state.json` — non-secret state (last mode, last plan hash, DNS backup path).
  - `dns-backup.json` — original per-adapter DNS and search lists.
  - `logs\` — optional ring logger, ACL'd to SYSTEM/Administrators and (read-only) the desktop user.
- The identified user should be able to *use* the VPN but not read the private key. The GUI sends
  the identity once during enrollment over the authenticated pipe; the service persists it and
  returns only redacted metadata afterwards.
- Never store the identity in `%APPDATA%` for the service to read: a per-user file cannot be read by
  LocalSystem reliably, and it puts the key in a user-writable location.

### 5.8 DNS, firewall, crash consistency

- **DNS:** enumerate active adapters (`winipcfg.GetAdaptersAddresses`), save their current DNS
  servers (`luid.DNS()`) and suffixes (`IPAdapterAddresses.DNSSuffix()`, plus the registry
  `SearchList` where present), then `luid.SetDNS(AF_INET, []netip.Addr{127.0.2.2, 127.0.2.3}, nil)`
  and the same for IPv6 (`::ffff:127.0.2.2` is what Cloudflare's client uses on Windows). Restore
  on disconnect and on startup if a backup exists. `FlushDNS` after changes. Only point DNS at
  `127.0.2.2/3` once the local DNS proxy exists; until then leave the resolver untouched rather
  than pointing it at a dead address. For domain-scoped fallback, NRPT (`DnsSetPolicy` /
  `netsh dns add policy`) is the Windows mechanism; add it when Local Domain Fallback is
  implemented.
- **Firewall / kill switch:** reuse
  [`golang.zx2c4.com/wireguard/windows/tunnel/firewall`](https://git.zx2c4.com/wireguard-windows/tree/tunnel/firewall)
  (MIT). It opens a WFP dynamic session and installs a block-all-plus-permits filter set:
  `EnableFirewall(luid, doNotRestrict, restrictToDNSServers)`. Its `permitWireGuardService` rule
  permits the calling process by AppID, which is what we want (our service). Two caveats:
  - It is a *block everything except the tunnel* kill switch, not a per-CIDR split-tunnel
    enforcement engine. Cloudflare's client also installs per-CIDR WFP filters to stop a
    routing-table bypass. If we need that parity, copy the package into `internal/winfw` (MIT
    permits it) and parameterize the filters; do not start from raw `fwpmu` syscalls.
  - A **dynamic** WFP session disappears if the service dies, i.e. fail-open on crash. Mullvad
    installs persistent filters at boot for fail-closed. Decide explicitly and document it. For a
    first cut, fail-open plus reliable service recovery is acceptable; if the org requires
    fail-closed, add a boot-time blocking provider like Mullvad's.
- **Crash consistency:** on service start, (1) delete stale `warpalt` Wintun adapters, (2) remove
  stale bypass routes on physical interfaces, (3) restore DNS from `dns-backup.json`, (4) clear the
  in-progress marker. On clean stop, do the same in reverse. On `SIGKILL`/power loss the marker is
  the only evidence; the startup reconcile is what makes it safe.

### 5.9 Packaging and updates

- MSI (WiX or Inno Setup) is the least surprising path: install to `%ProgramFiles%\warpalt\`,
  register the service, add Start Menu shortcut, and run the uninstaller elevated. A portable zip
  can still work through the one-time `--install-service` UAC flow.
- Sign `warpalt.exe` and `warpaltd.exe`. An unsigned service install works but shows "Unknown
  publisher" and will be blocked by some enterprise policies.
- Updates: stop the service, replace `warpaltd.exe` and `wintun.dll`, start the service. An
  in-app updater that writes to `%ProgramFiles%` needs elevation; MSI/patch is cleaner.
- Do not auto-install the service silently without consent; show what will be installed and why
  (the same thing every VPN client does).

---

## 6. Shared contract (both platforms)

### 6.1 Process model

```
warpalt        unprivileged    UI, enrollment, policy fetch, userspace proxy mode
warpaltd       privileged      tunnel + netconfig + secrets
```

One daemon per machine, one active tunnel per machine. If a second user connects, the daemon
rejects with "another user owns the tunnel" (or, later, per-user tunnels with per-user Wintun
adapters — out of scope).

### 6.2 RPC surface

Keep it deliberately small. Suggested methods (JSON-RPC, `net/rpc` style):

| Method | Purpose | Privileged? |
|---|---|---|
| `Ping` | version/capability handshake | no |
| `Status` | state, interface, addresses, since, last error, policy hash | no |
| `Connect(ConnectArgs)` | identity + plan + DNS + mode | yes |
| `Disconnect` | idempotent teardown | yes |
| `UpdatePlan(Plan)` | org policy/local routes changed while connected | yes |
| `PutIdentity(Identity)` | enrollment handoff; service persists it | yes (writes machine state) |
| `GetIdentity` | redacted metadata only (device id, team, addresses) | no |
| `Logout` | delete identity + teardown | yes |
| `Subscribe` | server pushes state events on a second connection | no |
| `Shutdown` | stop the daemon (root/Administrators only) | yes |

`ConnectArgs` never contains a path, command, URL to execute, or interface name. The daemon chooses
`warp0`/`warpalt`; the client only supplies data.

### 6.3 Validation and hardening

- **Message size:** `net/rpc/jsonrpc` has no built-in limit. Wrap the `net.Conn` so a single JSON
  value cannot exceed ~1 MiB (count bytes per read and error out), or use a length-prefixed codec.
- **Identity:** validate base64 key lengths, token length/prefix, `host:port` endpoints, and the
  assigned IPv4/IPv6 with `netip.ParseAddr`. Reject anything else.
- **Routes:** `netip.ParsePrefix`, reject default routes (we use `/1` pairs), cap the list (e.g.
  10,000 entries), deduplicate, reject prefixes with host bits set (or mask them), and keep the
  endpoint bypass list daemon-generated.
- **DNS:** max 8 servers, IP literals only, fixed port 53, no search-domain strings from the client
  (they come from policy and are validated as DNS names).
- **Rate limit:** one connect/disconnect per second; serialize state transitions with a mutex.
- **Logging:** never log the identity, bearer token, or private key. The current daemon logs the
  whole start command; do not carry that over.
- **No shell:** never pass client data to `exec`. The only subprocess allowed is `netsh`/`resolvectl`
  with fixed argument shapes built from validated values.

### 6.4 State machine and events

`disconnected → connecting → connected → disconnecting → disconnected`, plus `error` and
`reconnecting`. Every transition is broadcast to subscribers. The GUI never infers state from a
button; it renders `Status`.

### 6.5 Lifecycle

- Start: reconcile stale state → listen → announce `disconnected`.
- `Connect`: validate → create TUN → addresses/MTU/up → routes (with rollback) → DNS (with backup)
  → firewall → start engine → `connected`.
- Any failure: roll back in reverse order, restore DNS, remove routes, close TUN, `error` with a
  user-readable cause (`EPERM` → "service needs CAP_NET_ADMIN / the WARP service is not installed").
- `Disconnect`/shutdown/SIGTERM: stop engine → firewall off → DNS restore → routes off → TUN close.
- GUI disappearance must not tear down the tunnel (the daemon is independent). The GUI reconnects
  and reads status.

---

## 7. Reuse catalog: what not to write

| Need | Use | License | Replaces |
|---|---|---|---|
| WARP MASQUE/Connect-IP, enrollment, keepalive/reconnect, netstack adapters | `github.com/Diniboy1123/usque/api` (already vendored, v1.5.0) | MIT | An entire protocol client |
| Cross-platform TUN (Linux ioctl + Windows Wintun), fd access, netstack | `golang.zx2c4.com/wireguard/tun` (already vendored) | MIT | `songgao/water`, `internal/tun`, `internal/warp/tun_*` |
| Wintun adapter/session/rings | `golang.zx2c4.com/wintun` (already vendored) | MIT | Hand-written `wintun.dll` bindings |
| Windows addresses, routes, MTU, DNS, route-change notifications | `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` (already used) | MIT | `netsh`/`route.exe` parsing |
| Windows WFP kill switch | `golang.zx2c4.com/wireguard/windows/tunnel/firewall` | MIT | Raw `fwpmu` syscalls, a custom WFP engine |
| Windows service host / install / recovery | `golang.org/x/sys/windows/svc`, `.../svc/mgr` | BSD-3 | `sc.exe` wrappers, a service framework |
| Windows named pipes with SDDL, IOCP, remote-client rejection | `github.com/Microsoft/go-winio` | MIT | `CreateNamedPipe`/`ConnectNamedPipe` plumbing, ACL construction |
| One-time elevation | `windows.ShellExecute("runas", ...)` (x/sys) or an `elevate.exe`-style helper | BSD-3 | A custom UAC shim |
| Secret storage (Windows) | DPAPI (`windows.CryptProtectData`, machine scope) | BSD-3 | A custom crypto store |
| Linux link/address/route | `github.com/vishvananda/netlink` (already used) | Apache-2.0 | Netlink message construction |
| Linux firewall | `github.com/google/nftables` | Apache-2.0 | `iptables` shell-outs |
| Linux DNS via resolved | `github.com/godbus/dbus/v5` (already indirect) + `resolvectl` fallback | BSD-2 | A resolver-config parser |
| Linux service supervision/sandboxing | systemd | LGPL-2.1+ | A supervisor, pid files, privilege dropping |
| Linux service notifications | `github.com/coreos/go-systemd/v22/daemon` (optional) | Apache-2.0 | `NOTIFY_SOCKET` plumbing |
| Local DNS proxy (when implemented) | `github.com/miekg/dns` or `github.com/AdguardTeam/dnsproxy` | BSD-3 / Apache-2.0 | DNS packet parsing and DoH client |
| Userspace SOCKS5/HTTP proxy | usque's `socks`/`http-proxy` modes (or its `api` + a small SOCKS5 library) | MIT | A proxy implementation |

### What remains ours (roughly 0.8–1.2k LOC)

| Piece | ~LOC | Notes |
|---|---|---|
| Linux netconfig (TUN, addr, MTU, routes, rollback) | 250 | netlink + wireguard-go tun |
| Windows netconfig (adapter, addr, MTU, routes, rollback) | 250 | wintun/winipcfg |
| DNS set/restore (both) | 250 | resolved/file; winipcfg adapters |
| IPC server/client + peer verification + validation | 250 | stdlib rpc/jsonrpc + 60 lines of platform auth |
| Service host/install (both) | 200 | x/sys svc + systemd unit |
| Engine orchestration/state machine | 150 | usque api |
| Firewall policy wiring | 100 | nft/WFP calls |

That is the irreducible supervisor. It contains no QUIC, no TLS, no driver, no pipe framing, no
TUN ioctls, and no firewall engine.

### Whole daemons considered and rejected

- **Delegate to Cloudflare's `warp-svc` / WARP service.** It would make warpalt a `warp-cli`
  wrapper, contradicting the project's premise, and it does not expose the org profile or the
  split-tunnel control this app needs.
- **`tailscaled` / `tsnet`.** Tailscale's protocol and control plane, not WARP.
- **`sing-box` / `mihomo` / `tun2socks` / `wireproxy`.** Good TUN/proxy engines, but none speaks
  MASQUE/WARP with Zero Trust enrollment. `wireproxy` is WireGuard-to-SOCKS only.
- **`tailscale.com/safesocket`.** Attractive (Unix socket + Windows pipe + peer checks), but it
  pulls the `tailscale.com` module and its feature plumbing for one small package. `net.Listen("unix")`
  plus `go-winio` is lighter and has fewer version constraints.

---

## 8. Two modes

| | System tunnel (default) | Userspace proxy (no privilege) |
|---|---|---|
| Install | systemd service / Windows service (one-time admin or MSI) | none |
| Scope | all apps, system-wide routes | only apps configured with the proxy (or `socks5h://`) |
| DNS | system resolver pointed at our proxy / Gateway | proxy-side resolution (`socks5h`) or local resolver |
| Split tunnel | full org policy, include/exclude, firewall | not enforceable system-wide |
| Kill switch | possible (nftables/WFP) | not possible |
| Auto-start | boot / service start | user login only |
| Windows without admin | impossible | the only option |
| Linux containers/CI | needs caps or a privileged unit | works |

Ship both. The userspace mode is not a downgrade of the product; it is the answer to "I cannot
install a service" (locked-down Windows, containers, immutable Linux, CI). usque already implements
the hard parts: `socks`, `http-proxy`, `l4-socks`, `l4-http-proxy`, with a netstack that needs no
TUN. The GUI can expose it as "Proxy mode (no admin)".

---

## 9. Implementation plan

### Phase 0 — make the tree build, remove duplication

1. Delete `internal/tun` and `internal/tunnel`; stop compiling them.
2. Move the platform TUN code into the new daemon package (`internal/netcfg`), using
   `wireguard-go/tun` instead of `water`.
3. Fix or remove `internal/app` (`wails.Window`/`CurrentWindow` are not Wails v2) and
   `internal/settings` (`warp.Dir`). Keep `internal/warp` as the engine (usque).
4. Add `cmd/warpaltd` (no Wails imports) and keep `main.go` for the GUI.

### Phase 1 — Linux

1. `internal/protocol`: RPC types + version.
2. `internal/daemon`: state machine, validation, JSON-RPC server, `SO_PEERCRED`.
3. `internal/netcfg/linux`: TUN + addresses + routes + rollback + DNS + optional nftables.
4. systemd unit, sysusers, install scripts; `Type=notify`.
5. Crash-reconcile (DNS backup, stale socket, left-over nft table).
6. Acceptance: standard user starts GUI, connects, `ip route get 1.1.1.1` shows the tunnel,
   disconnect restores the table and resolver, `kill -9` + restart restores cleanly.

### Phase 2 — Windows

1. `internal/winpipe`: go-winio pipe + SDDL + PID→token.
2. `internal/daemon` service host (`svc.Run`), install/uninstall commands.
3. `internal/netcfg/windows`: wintun/`tun.CreateTUN`, winipcfg addresses/routes/MTU (via the
   `IPInterface` row), DNS save/restore.
4. WFP: import the wireguard package; if per-CIDR enforcement is needed, copy it into
   `internal/winfw` and parameterize.
5. MSI (or first-run UAC) + service recovery + `%ProgramData%` DPAPI.
6. Acceptance: standard user account (not Administrators), GUI runs without UAC, connect works,
   pipe is denied to a second account, service restart cleans up, reboot auto-connects if enabled.

### Phase 3 — parity

- Split tunnel from the org profile + local additions. Keep policy/hostname resolution in the
  GUI, and send the resulting validated CIDR plan to the daemon as data (the daemon must not
  fetch policy or resolve hostnames).
- DNS proxy (`127.0.2.2/3`) + Gateway DoH inside the tunnel.
- Kill switch UI + explicit fail-open/fail-closed choice.
- Userspace proxy mode (usque socks/http-proxy).

### Phase 4 — packaging

- deb/rpm + NixOS module; MSI; signed binaries; uninstall tests.

---

## 10. Verification performed for this document

Run in this workspace on 2026-10-26 (Linux, uid 1000, no effective capabilities):

1. **Pre-implementation build baseline** — `go build ./internal/...` failed exactly as listed in
   §3. That is why the daemon was rebuilt rather than extended; the implementation-status section
   above records what replaced it.
2. **TUN fd passing + peer credentials** — a small Go program using
   `unix.Sendmsg`/`unix.UnixRights`/`unix.Recvmsg`/`unix.ParseUnixRights` passed a file descriptor
   over a `socketpair` and read from it, and `unix.GetsockoptUcred(SOL_SOCKET, SO_PEERCRED)`
   returned `pid=… uid=1000 gid=100`. Both mechanisms the Linux design relies on work with the
   project's `golang.org/x/sys` version.
3. **Unprivileged user namespaces** — `unshare -Urn sh -c 'ip tuntap add dev warptest0 mode tun'`
   succeeded on this host, confirming that the "per-namespace TUN without root" option is real
   where the distro allows unprivileged userns. It does not make the system-wide tunnel
   unprivileged, because apps outside the namespace do not use it.
4. **Windows claims** are source-verified against wintun, wireguard-windows and Microsoft docs
   (links below), not runtime-tested: this environment has no Windows host. Treat the Wintun ACL,
   WFP, pipe and service details as code-review findings to validate on a Windows VM in Phase 2.

---

## 11. Open decisions

1. **Linux DNS backend policy**: resolved-only (no root needed with a polkit rule), or
   resolv.conf fallback (root)? Recommendation: resolved first, file fallback, and log it.
2. **Linux dataplane split**: keep the engine in `warpaltd` (Mullvad/Tailscale model) or hand the
   TUN fd to a dedicated unprivileged worker (OpenVPN 3 model)? Recommendation: in-process first;
   the fd handoff is a small, isolated Phase 2 change if the threat model demands it.
3. **Kill switch failure mode**: fail-open with fast service restart, or persistent fail-closed
   filters at boot (Mullvad)? This is a product/compliance decision, not a technical one.
4. **Windows install channel**: MSI-first, or first-run UAC from a portable zip (or both)?
5. **Windows per-CIDR split-tunnel firewall**: routes-only for v1, or copy/parameterize the WFP
   filters to match Cloudflare's "firewall enforces split tunnel" behaviour?
6. **Service user on Linux**: root with bounded caps (simple, works with resolv.conf) vs dedicated
   user + ambient caps + polkit rule (more work, no root). Recommendation: root + sandbox for v1.
7. **macOS**: the tree has darwin stubs; do not claim support until there is a real
   `utun`/`NEPacketTunnelProvider` design. It is a separate research task.

---

## 12. Sources

Primary sources read for this document:

- Cloudflare One Client architecture (service/daemon + GUI, DNS proxy, routing, firewall):
  https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/client-architecture/
- Cloudflare WARP on Linux (`warp-svc`, `warp-cli`, MASQUE default):
  https://developers.cloudflare.com/warp-client/get-started/linux/
- Cloudflare Local Domain Fallback:
  https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/local-domains/
- Linux kernel TUN/TAP documentation (CAP_NET_ADMIN, persistent devices, fd semantics):
  https://docs.kernel.org/networking/tuntap.html
- Wintun source: `api/main.c` (security attributes), `api/namespace.c` (SYSTEM/Administrators
  boundary), `driver/wintun.c` (device SDDL and `SeAccessCheck`):
  https://git.zx2c4.com/wintun/tree/api/main.c
  https://git.zx2c4.com/wintun/tree/api/namespace.c
  https://git.zx2c4.com/wintun/tree/driver/wintun.c
- Wintun API reference:
  https://git.zx2c4.com/wintun/about/
- WireGuard for Windows, enterprise/service architecture:
  https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md
- WireGuard for Windows source: `tunnel/service.go`, `tunnel/firewall/`, `tunnel/winipcfg/`,
  `manager/ipc_server.go`, `elevate/`, `conf/dpapi/`:
  https://git.zx2c4.com/wireguard-windows/tree/tunnel/
- Microsoft, Named Pipe Security and Access Rights (default ACLs, logon SID guidance):
  https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- go-winio pipe implementation (`PipeConfig`, `FILE_PIPE_REJECT_REMOTE_CLIENTS`, impersonation
  levels):
  https://github.com/microsoft/go-winio/blob/main/pipe.go
- Mullvad VPN app security architecture (root daemon, UDS/named pipe, nftables/WFP, threat model):
  https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md
- OpenVPN 3 Linux D-Bus architecture (root netcfg service, unprivileged backend, `Establish`
  returning a TUN fd):
  https://github.com/OpenVPN/openvpn3-linux/blob/master/docs/dbus/dbus-overview.md
  https://github.com/OpenVPN/openvpn3-linux/blob/master/src/netcfg/proxy-netcfg-device.cpp
- usque (MASQUE engine, native TUN, SOCKS5/HTTP proxy modes, MIT):
  https://github.com/Diniboy1123/usque
- systemd service hardening (`AmbientCapabilities`, `CapabilityBoundingSet`, sandboxing):
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
