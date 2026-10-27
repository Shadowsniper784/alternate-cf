//go:build windows

package netcfg

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// DefaultMTU keeps every packet inside the MASQUE/QUIC path MTU.
const DefaultMTU = 1280

// AdapterName is fixed so a restarted service reuses the adapter created by
// the previous run instead of leaking a new one on every start.
const AdapterName = "warpalt"

// Device is a configured Wintun adapter owned by the daemon.
type Device struct {
	dev  tun.Device
	name string
	luid winipcfg.LUID
}

// Cleanup removes stale routes from a previous crashed service run. The
// Wintun adapter survives process exit, so without this the old /1 routes
// would blackhole traffic between a crash and the next Connect.
func Cleanup() {
	ifi, err := net.InterfaceByName(AdapterName)
	if err != nil {
		return
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(ifi.Index))
	if err != nil {
		return
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		_ = luid.FlushRoutes(family)
	}
}

// Device exposes the packet interface to the tunnel engine.
func (d *Device) Device() tun.Device { return d.dev }

// Name is the adapter's interface name.
func (d *Device) Name() string { return d.name }

// Close releases the Wintun session. The adapter itself is intentionally left
// in place so the next start is fast and address configuration is idempotent.
func (d *Device) Close() error {
	if d.dev == nil {
		return nil
	}
	err := d.dev.Close()
	d.dev = nil
	return err
}

// Create opens the Wintun adapter, assigns addresses, sets the MTU and leaves
// the adapter up. Requires administrator rights: a non-admin process cannot
// open the adapter's kernel device at all.
func Create(ipv4, ipv6 string, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	dev, err := tun.CreateTUN(AdapterName, mtu)
	if err != nil {
		return nil, fmt.Errorf("creating Wintun adapter (the service must run as LocalSystem): %w", err)
	}

	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("reading adapter name: %w", err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("locating adapter %s: %w", name, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("resolving adapter LUID: %w", err)
	}

	var prefixes []netip.Prefix
	for _, spec := range []string{ipv4, ipv6} {
		if spec == "" {
			continue
		}
		p, err := parsePrefix(spec)
		if err != nil {
			_ = dev.Close()
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) > 0 {
		// Set (not Add) keeps restart idempotent even when the adapter is
		// reused and still carries addresses from the previous session.
		if err := luid.SetIPAddresses(prefixes); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("assigning tunnel addresses: %w", err)
		}
	}

	// Set the interface MTU through the IP interface row. This is the same
	// path WireGuard's Windows client uses and avoids shelling out to netsh.
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, err := luid.IPInterface(family)
		if err != nil {
			continue
		}
		ipif.NLMTU = uint32(mtu)
		// Windows breaks ties between equal-length routes by interface
		// metric, and Wintun's automatic metric usually beats the physical
		// adapter's. That would pull the machine's own broadcast and
		// multicast discovery into the tunnel. A high metric makes the
		// adapter lose those ties; the /1 routes still win on prefix length
		// for everything the tunnel is supposed to carry.
		ipif.UseAutomaticMetric = false
		ipif.Metric = 5000
		_ = ipif.Set()
	}

	return &Device{dev: dev, name: name, luid: luid}, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address %q: %w", s, err)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
