//go:build !linux && !windows

package netcfg

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// DefaultMTU keeps every packet inside the MASQUE/QUIC path MTU.
const DefaultMTU = 1280

// Cleanup is a no-op on unsupported platforms.
func Cleanup() {}

// Device is a placeholder so the daemon and GUI still build on platforms
// without a TUN backend yet.
type Device struct {
	dev  tun.Device
	name string
}

func (d *Device) Device() tun.Device { return d.dev }
func (d *Device) Name() string       { return d.name }

func (d *Device) Close() error {
	if d.dev == nil {
		return nil
	}
	return d.dev.Close()
}

// Create reports that this platform has no netcfg implementation.
func Create(string, string, int) (*Device, error) {
	return nil, errors.New("warpaltd has no TUN backend for this platform yet (linux and windows are supported)")
}
