//go:build !windows

package daemon

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"warpalt/internal/control"
)

// listen creates the control socket. It refuses to replace anything that is
// not already a socket, which prevents a symlink attack on a world-writable
// directory.
func listen() (net.Listener, error) {
	path := control.SocketPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating control socket directory %s (run as root, or set WARPALT_SOCKET): %w", dir, err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale control socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("setting control socket mode: %w", err)
	}
	// If the packaging created a warpalt group, hand the socket to it. Without
	// the group the mode still limits access to root and the owner. A non-root
	// development run must not try to chown to root.
	//
	// Without packaging there is no warpalt group either, and a root:root 0660
	// socket would lock out the desktop user entirely (permission denied on
	// every status call). In that case fall back to the primary group of the
	// user who launched us through sudo, so exactly that user's session can
	// reach the control channel.
	if os.Geteuid() == 0 && !control.ForceDevRun {
		gid := -1
		if g, err := user.LookupGroup("warpalt"); err == nil {
			if n, err := strconv.Atoi(g.Gid); err == nil {
				gid = n
			}
		} else if s := os.Getenv("SUDO_GID"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				gid = n
			}
		}
		if gid >= 0 {
			if err := os.Chown(path, 0, gid); err != nil {
				_ = l.Close()
				return nil, fmt.Errorf("changing control socket owner: %w", err)
			}
		}
	}
	if fi, err := os.Lstat(path); err == nil {
		vlogf("control socket %s %s", path, fi.Mode())
	}
	return l, nil
}
