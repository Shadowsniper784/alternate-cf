//go:build !windows

package control

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

var errUnavailable = errors.New("warpaltd is not running")

var consolePath = os.Getenv("WARPALT_DAEMON_CONSOLE")

// SocketPath is the Unix socket the daemon listens on. The environment
// override exists for development and for tests; the packaged service uses
// the default under /run.
func SocketPath() string {
	if p := os.Getenv("WARPALT_SOCKET"); p != "" {
		return p
	}
	return "/run/warpalt/control.sock"
}

// ForceDevRun is set by the development launcher when the daemon is started
// by the GUI process itself rather than by the systemd unit. It disables the
// chown step in listen_unix.go so a root-launched socket can be used by the
// same user who launched the GUI.
var ForceDevRun = os.Getenv("WARPALT_DEV_RUN") != ""

// Endpoint names the control channel endpoint for log lines.
func Endpoint() string { return SocketPath() }

func dial(timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("unix", SocketPath(), timeout)
	if err != nil && consolePath != "" {
		fmt.Fprintf(os.Stderr, "[warpaltd] %v\n", err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrUnavailable, SocketPath(), err)
	}
	return c, nil
}
