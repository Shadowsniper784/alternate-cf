//go:build windows

package daemon

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"warpalt/internal/control"
)

// pipeSDDL grants full control to LocalSystem and Administrators and
// read/write to interactive users. The GUI is asInvoker, so the user's own
// token is the one that connects.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

func listen() (net.Listener, error) {
	l, err := winio.ListenPipe(control.PipeName(), &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
	})
	if err != nil {
		return nil, fmt.Errorf("creating control pipe %s (is the service running as LocalSystem?): %w", control.PipeName(), err)
	}
	return l, nil
}

// authorize rejects the non-interactive service accounts. The pipe DACL is the
// primary gate; this blocks a low-privilege service that happens to run as an
// interactive user's SID from driving the tunnel.
func authorize(c net.Conn) error {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return nil
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return fmt.Errorf("identifying pipe client: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("opening client process %d: %w", pid, err)
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("opening client token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("reading client user: %w", err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalServiceSid) ||
		user.User.Sid.IsWellKnown(windows.WinNetworkServiceSid) {
		return fmt.Errorf("service accounts may not control the tunnel")
	}
	return nil
}
