# Handover Notes — warpalt

## What this repo is

warpalt is a WARP/tunnel client project with two runtime targets:

- `internal/warpdaemon` — a privileged daemon that owns the system TUN device and routes, talks over a Unix socket, and broadcasts tunnel state.
- `warpalt` (top-level `main.go`) — a Wails desktop app that drives enrollment/profile/config and communicates with the daemon.

Routing is split into `internal/routes` (Linux/Windows route manipulation), and the TUN layer is split across platform-specific packages.

## Current states

### Compiled
- `internal/warpdaemon`: can build cleanly with `go build -tags "production" -trimpath -o /tmp/warpdaemon ./internal/warpdaemon`.

### Not yet compiling / blocked
- `internal/tun`: does not compile under Linux currently. The Linux file `internal/tun/tun_linux.go` is live for Linux builds (`//go:build linux`), but it currently references symbols in a way that still leaves the tun package unable to resolve its own types. Concretely, `Identity` and `Interface` naming/ownership is not settled in a way that survives the full package cycle.

Important detail: under Linux, Go resolves `./internal/tun` from only `tun_linux.go`. The fallback file `internal/tun/tun.go` is tagged `//go:build !linux`, so it is ignored on Linux. That means the tun package cannot simply depend on `tun.go` for type definitions on Linux.

## Main design tension

The project is trying to split the TUN implementation into two layers, and that split is the source of the remaining cycle/weirdness:

- `internal/warp` — higher-level tunnel logic, wants to own create/configure/lifecycle for `Identity`.
- `internal/tun` — platform TUN device package, currently still wanting to consume `warp.Identity` directly on Linux.

On Linux, the current Linux tun file imports `warpalt/internal/warp` and uses `*warp.Identity`, which is how the cycle starts showing up depending on what else imports what.

## Where things are by package

### `internal/warp`
- `identity.go` owns the main `Identity` type.
- `tun_linux.go` still holds the Linux TUN creation path and references a `linuxTunnel` shaped object plus `warpTunnel` / `NewInterface` bridge stuff.
- `tunnel.go` was rewritten to a cleaner shape that avoids importing `internal/tun` from the core tunnel file. It now has a hard-coded `createInterface` fallback that returns an error saying device creation is not wired for the current build.

### `internal/tun`
- `tun.go` is the non-Linux fallback. It defines `Interface`, `Identity`, and a no-op `Create`.
- `tun_linux.go` is the active Linux implementation. It imports `water`, `netlink`, and `warpalt/internal/warp`, and uses `*warp.Identity` in `Create(...)`.

### `internal/routes`
- `apply_linux.go` has real-ish Linux route helper scaffolding (`captureDefault`, `captureDefault4`, `captureDefault6`, `prefixIPNet`) but `Apply` is still essentially a placeholder returning an empty handle.
- `plan.go` owns `Plan` and `BuildRoutePlan`.
- There was earlier churn around duplicated `Plan`-ish types; the current set should be read before assuming anything is duplicated.

### `internal/warpdaemon`
- `interface.go` defines `Interface` and `Connection` for the daemon socket layer.
- `listener_linux.go` implements the Unix socket listener.
- `daemon.go` is the core loop.

### `internal/tunnel`
- There is a parallel `internal/tunnel` package with its own platform dispatch files (`tunnel_linux.go`, `tunnel_windows.go`, `tunnel_darwin.go`, etc.).
- That package is partially redundant with the `internal/warp` + `internal/tun` arrangement and partly unused, depending on which entry points you follow.

## Likely next move

The cleanest resolution is probably one of these:

1. Let `internal/tun` define its own lean `Identity` struct on Linux and keep it independent of `internal/warp`, and let `internal/warp` convert its `Identity` into that tun-level type at the boundary.
2. Or, if Linux TUN really must live in `internal/tun` and must know about identity fields, reduce the dependency so there is no import of `internal/warp` from `internal/tun` on Linux.

Right now, the fallback placeholder in `internal/warp/tunnel.go` keeps the daemon build passing even while the tun package is still broken, so it is easy to lose track of the fact that the tun package itself is not healthy.

## Concrete things to verify before continuing

- Read `internal/tun/tun_linux.go` and `internal/tun/tun.go` together, remembering that on Linux only `tun_linux.go` is compiled.
- Confirm whether `waralt/internal/tun` on Linux needs its own `Identity`, or whether callers should pass an already-materialized config through a boundary type.
- Decide whether `internal/tunnel` should be kept, folded into `internal/warp`, or removed.
- Decide whether Linux `Apply` in `internal/routes/apply_linux.go` should be finished enough to be real, or whether the daemon should keep using the placeholder until routing is intentionally deferred.

## Local build commands

Standard checks used in this session:

- `nix develop -c bash -c 'go build -tags "production" -trimpath -o /tmp/warpdaemon ./internal/warpdaemon'`
- `nix develop -c bash -c 'go vet ./...'`

There is also a `Makefile` with `build-daemon`, `build-app`, `dev`, `check-daemon`, `install-cap`, and `restart-daemon` targets.

## Files to read before big changes

- `internal/tun/tun_linux.go`
- `internal/tun/tun.go`
- `internal/warp/tun_linux.go`
- `internal/warp/tunnel.go`
- `internal/warp/identity.go`
- `internal/routes/apply_linux.go`
- `internal/routes/plan.go`
- `internal/tunnel/tunnel_linux.go`
- `internal/tunnel/tunnel.go`
- `internal/warpdaemon/interface.go`
- `internal/warpdaemon/listener_linux.go`
