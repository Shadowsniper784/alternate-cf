//go:build linux

// Package netcfg creates and configures the platform TUN device. It is only
// linked into warpaltd, which is the only process that holds the capability to
// do this. The GUI never imports it.
package netcfg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// DefaultMTU keeps every packet inside the MASQUE/QUIC path MTU.
const DefaultMTU = 1280

// Cleanup is a no-op on Linux: the TUN device is non-persistent and the
// kernel removes its routes when the owning process exits.
func Cleanup() {}

// Device is a configured TUN interface owned by the daemon.
type Device struct {
	dev  tun.Device
	name string
}

// Device exposes the packet interface to the tunnel engine.
func (d *Device) Device() tun.Device { return d.dev }

// Name is the kernel interface name.
func (d *Device) Name() string { return d.name }

// Close releases the TUN device. A non-persistent device also disappears from
// the kernel, so there is no link left behind.
func (d *Device) Close() error {
	if d.dev == nil {
		return nil
	}
	err := d.dev.Close()
	d.dev = nil
	return err
}

// Create opens a TUN device, sets its addresses and MTU and brings it up.
// Requires CAP_NET_ADMIN. The interface name is chosen by the daemon, never by
// the caller.
func Create(ipv4, ipv6 string, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	var dev *plainTun
	var name string
	var err error
	for i := 0; i < 8; i++ {
		name = fmt.Sprintf("warp%d", i)
		dev, err = openTun(name, mtu)
		if err == nil {
			break
		}
		// A missing /dev/net/tun or missing capability cannot be fixed by
		// trying another name, so fail fast with the actionable error.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("creating TUN device (the service needs CAP_NET_ADMIN and /dev/net/tun): %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("creating TUN device (the service needs CAP_NET_ADMIN and /dev/net/tun): %w", err)
	}

	if err := configureLink(name, ipv4, ipv6, mtu); err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &Device{dev: dev, name: name}, nil
}

func configureLink(name, ipv4, ipv6 string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("locating link %s: %w", name, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("setting MTU %d: %w", mtu, err)
	}
	for _, spec := range []string{ipv4, ipv6} {
		if spec == "" {
			continue
		}
		prefix, err := parsePrefix(spec)
		if err != nil {
			return err
		}
		addr := &netlink.Addr{IPNet: prefixToIPNet(prefix)}
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("adding address %s: %w", prefix, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing link up: %w", err)
	}
	return nil
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

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

// plainTun is a TUN device without IFF_VNET_HDR. wireguard-go's CreateTUN
// always enables the virtio header, which forces every writer to prefix
// packets with a virtio_net_hdr (usque's adapter does not) and lets the
// kernel hand back GSO super-packets that a single-buffer reader cannot
// split. A plain device carries raw IP packets in both directions, which is
// exactly what the MASQUE engine exchanges.
type plainTun struct {
	f      *os.File
	name   string
	mtu    int
	events chan tun.Event
	once   sync.Once
}

func openTun(name string, mtu int) (*plainTun, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &plainTun{
		f:      os.NewFile(uintptr(fd), "/dev/net/tun"),
		name:   name,
		mtu:    mtu,
		events: make(chan tun.Event, 4),
	}, nil
}

func (t *plainTun) File() *os.File { return t.f }

func (t *plainTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.f.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *plainTun) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, b := range bufs {
		if _, err := t.f.Write(b[offset:]); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (t *plainTun) MTU() (int, error)        { return t.mtu, nil }
func (t *plainTun) Name() (string, error)    { return t.name, nil }
func (t *plainTun) Events() <-chan tun.Event { return t.events }
func (t *plainTun) BatchSize() int           { return 1 }

func (t *plainTun) Close() error {
	var err error
	t.once.Do(func() {
		close(t.events)
		err = t.f.Close()
	})
	return err
}
