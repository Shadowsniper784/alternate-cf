//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// authorize checks the peer credentials behind the socket. The socket's mode
// is the first gate; this is defence in depth against a socket that was
// accidentally made world-accessible.
func authorize(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred.Uid == 0 || int(cred.Uid) == os.Geteuid() {
		return nil
	}
	g, err := user.LookupGroup("warpalt")
	if err != nil {
		// No packaging group: the 0660 root-owned socket is the access model.
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil
	}
	if int(cred.Gid) == gid || peerInGroup(int(cred.Pid), gid) {
		return nil
	}
	return fmt.Errorf("uid %d is not in the warpalt group", cred.Uid)
}

// peerInGroup reads the peer's supplementary groups. On systems with a
// hardened /proc (hidepid=2) the read fails; the socket mode remains the gate
// and we do not turn that into a false rejection.
func peerInGroup(pid, gid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Groups:") {
			continue
		}
		for _, field := range strings.Fields(strings.TrimPrefix(line, "Groups:")) {
			if n, err := strconv.Atoi(field); err == nil && n == gid {
				return true
			}
		}
		return false
	}
	return false
}
