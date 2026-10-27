//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const systemdInstructions = `warpaltd is installed by the package into /usr/lib/systemd/system/warpaltd.service.

  sudo systemctl daemon-reload
  sudo systemctl enable --now warpaltd

The service creates /run/warpalt/control.sock (root:warpalt, 0660). Add your
desktop user to the warpalt group and log in again:

  sudo usermod -aG warpalt "$USER"

For a foreground run during development:

  WARPALT_SOCKET=/tmp/warpalt.sock sudo -E ./warpaltd
`

// Main runs the daemon, or prints service-management instructions.
func Main(install, uninstall, console bool) error {
	if install || uninstall {
		fmt.Print(systemdInstructions)
		return nil
	}
	_ = console

	d := New()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() { errCh <- d.Serve() }()

	select {
	case <-sig:
		_ = d.Close()
		return <-errCh
	case err := <-errCh:
		return err
	}
}
