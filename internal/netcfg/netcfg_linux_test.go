//go:build linux

package netcfg

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/vishvananda/netlink"
)

func TestCreateAndClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or a user+network namespace (unshare -Urn)")
	}
	dev, err := Create("172.16.0.2", "fd00::2", 1280)
	if err != nil {
		t.Skipf("TUN unavailable in this environment: %v", err)
	}
	name := dev.Name()
	if name == "" {
		t.Fatal("empty interface name")
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("link %s not found: %v", name, err)
	}
	if link.Attrs().MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", link.Attrs().MTU)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("address list: %v", err)
	}
	found4, found6 := false, false
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		ones, _ := a.IPNet.Mask.Size()
		switch {
		case a.IPNet.IP.To4() != nil && a.IPNet.IP.String() == "172.16.0.2" && ones == 32:
			found4 = true
		case a.IPNet.IP.To4() == nil && a.IPNet.IP.String() == "fd00::2" && ones == 128:
			found6 = true
		}
	}
	if !found4 || !found6 {
		t.Errorf("assigned addresses missing (v4=%v v6=%v): %v", found4, found6, addrs)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := netlink.LinkByName(name); err == nil {
		t.Errorf("link %s still exists after Close", name)
	}
}

// TestPacketRoundTrip writes a packet through the same adapter the MASQUE
// engine uses. Before the plain (no IFF_VNET_HDR) TUN this failed with
// "invalid offset", because wireguard-go requires a virtio header on every
// write while usque's adapter sends raw IP packets.
func TestPacketRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or a user+network namespace (unshare -Urn)")
	}
	const addr = "172.16.0.2"
	dev, err := Create(addr, "", 1280)
	if err != nil {
		t.Skipf("TUN unavailable in this environment: %v", err)
	}
	defer dev.Close()

	// The address is a /32, so add the on-link route the reply needs to find
	// its way back out of the interface.
	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		t.Fatalf("locating link: %v", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       &net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(24, 32)},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		t.Fatalf("adding on-link route: %v", err)
	}

	adapter := api.NewNetstackAdapter(dev.Device())
	found := make(chan []byte, 1)
	stop := make(chan struct{})
	defer close(stop)
	// The kernel emits IPv6 router solicitations as soon as the link comes up,
	// so keep reading until the echo reply shows up.
	go func() {
		buf := make([]byte, 1280)
		for {
			n, err := adapter.ReadPacket(buf)
			if err != nil {
				found <- nil
				return
			}
			if n >= 28 && buf[9] == 1 && buf[20] == 0 {
				found <- append([]byte(nil), buf[:n]...)
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	if err := adapter.WritePacket(icmpEchoRequest("172.16.0.99", addr)); err != nil {
		t.Fatalf("writing packet to TUN: %v", err)
	}

	select {
	case reply := <-found:
		if reply == nil {
			t.Fatal("reading from TUN failed")
		}
		if len(reply) < 28 {
			t.Fatalf("reply too short: %d bytes", len(reply))
		}
		if reply[9] != 1 || reply[20] != 0 {
			t.Fatalf("not an ICMP echo reply: proto=%d type=%d len=%d hex=%x", reply[9], reply[20], len(reply), reply)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ICMP echo reply from the kernel within 5s")
	}
}

// icmpEchoRequest builds an IPv4/ICMP echo request from src to dst so the
// kernel answers out of the same interface.
func icmpEchoRequest(srcAddr, dstAddr string) []byte {
	src := net.ParseIP(srcAddr).To4()
	dst := net.ParseIP(dstAddr).To4()
	payload := []byte("warpalt-ping")
	b := make([]byte, 20+8+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:], 0x1234)
	b[8] = 64
	b[9] = 1 // ICMP
	copy(b[12:16], src)
	copy(b[16:20], dst)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))

	icmp := b[20:]
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:], 0x4242)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
	return b
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
