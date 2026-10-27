//go:build darwin

package daemon

import "net"

// authorize on Darwin relies on the socket's 0660 ownership. local
// peer-credential checks need a different API and are not part of the
// supported deployment yet.
func authorize(net.Conn) error { return nil }
