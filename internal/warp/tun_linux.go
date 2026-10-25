//go:build linux

package warp

import (
	"fmt"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const tunMTU = 1280

// createTUN opens a TUN device, assigns the registration's tunnel addresses,
// sets the MTU and brings the link up. Requires CAP_NET_ADMIN (root).
func createTUN(id *Identity) (*water.Interface, error) {
	dev, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:   "warp%d",
			Persist: false,
		},
	})
	if err != nil {
		return nil, err
	}

	name := dev.Name()
	link, err := netlink.LinkByName(name)
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("locating link %s: %w", name, err)
	}

	if err := netlink.LinkSetMTU(link, tunMTU); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("setting MTU: %w", err)
	}
	if id.IPv4 != "" {
		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{IP: net.ParseIP(id.IPv4), Mask: net.CIDRMask(32, 32)},
		}); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("adding IPv4 address: %w", err)
		}
	}
	if id.IPv6 != "" {
		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{IP: net.ParseIP(id.IPv6), Mask: net.CIDRMask(128, 128)},
		}); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("adding IPv6 address: %w", err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("bringing link up: %w", err)
	}

	return dev, nil
}
