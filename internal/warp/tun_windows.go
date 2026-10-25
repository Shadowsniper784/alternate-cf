//go:build windows

package warp

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunMTU = 1280

// createTUN opens a TUN device (wintun) and assigns the registration's
// tunnel addresses. Requires administrator privileges and wintun.dll next to
// the executable.
func createTUN(id *Identity) (*water.Interface, error) {
	dev, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{},
	})
	if err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(dev.Name())
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("locating tunnel interface: %w", err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("resolving tunnel interface LUID: %w", err)
	}

	if id.IPv4 != "" {
		addr, err := netip.ParseAddr(id.IPv4)
		if err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("invalid tunnel IPv4 %q: %w", id.IPv4, err)
		}
		if err := luid.AddIPAddress(netip.PrefixFrom(addr, 32)); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("adding IPv4 address: %w", err)
		}
	}
	if id.IPv6 != "" {
		addr, err := netip.ParseAddr(id.IPv6)
		if err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("invalid tunnel IPv6 %q: %w", id.IPv6, err)
		}
		if err := luid.AddIPAddress(netip.PrefixFrom(addr, 128)); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("adding IPv6 address: %w", err)
		}
	}

	// Set the interface MTU so the MASQUE path's 1280-byte frames fit. This
	// goes through netsh because winipcfg cannot write MTU (MibIfRow2 has no
	// setter); failure is non-fatal, the default MTU is usually usable.
	for _, family := range []string{"ipv4", "ipv6"} {
		cmd := exec.Command("netsh", "interface", family, "set", "subinterface",
			dev.Name(), fmt.Sprintf("mtu=%d", tunMTU), "store=persistent")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("warning: could not set %s MTU via netsh: %v (%s)\n", family, err, strings.TrimSpace(string(out)))
		}
	}

	return dev, nil
}
