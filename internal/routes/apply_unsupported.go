//go:build !linux && !windows

package routes

import "fmt"

// Handle is the rollback handle for installed routes. Only Linux and Windows
// are supported by warpalt.
type Handle struct{}

// Remove is a no-op on unsupported platforms.
func (h *Handle) Remove() error { return nil }

// Apply reports that this platform is not supported.
func Apply(plan Plan, tunIface string) (*Handle, error) {
	return nil, fmt.Errorf("split-tunnel routing is not implemented for this platform (linux/windows only)")
}
