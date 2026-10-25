//go:build linux

package routes

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Handle represents installed routes that can be removed again.
type Handle struct {
	installed []netlink.Route
}

// Remove deletes every route this handle installed (idempotent).
func (h *Handle) Remove() error {
	var firstErr error
	for i := len(h.installed) - 1; i >= 0; i-- {
		r := h.installed[i]
		if err := netlink.RouteDel(&r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.installed = nil
	return firstErr
}

// Apply installs the plan: capture the current default route first, then add
// the tunnel routes on the TUN device and the bypass routes on the original
// interface via the original gateway. If any install fails, everything added
// so far is rolled back.
func Apply(plan Plan, tunIface string) (*Handle, error) {
	tunLink, err := netlink.LinkByName(tunIface)
	if err != nil {
		return nil, fmt.Errorf("finding tunnel interface %q: %w", tunIface, err)
	}

	gw, origIdx, err := captureDefault()
	if err != nil {
		return nil, err
	}

	h := &Handle{}
	rollback := func(cause error) (*Handle, error) {
		_ = h.Remove()
		return nil, cause
	}

	for _, p := range plan.ViaTunnel {
		r := netlink.Route{
			LinkIndex: tunLink.Attrs().Index,
			Dst:       prefixIPNet(p),
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAdd(&r); err != nil {
			return rollback(fmt.Errorf("adding tunnel route %s: %w", p, err))
		}
		h.installed = append(h.installed, r)
	}

	for _, p := range plan.Bypass {
		if !gw.IsValid() || origIdx <= 0 {
			return rollback(fmt.Errorf("no default route to install bypass %s", p))
		}
		r := netlink.Route{
			LinkIndex: origIdx,
			Dst:       prefixIPNet(p),
			Gw:        gw.AsSlice(),
		}
		if err := netlink.RouteAdd(&r); err != nil {
			return rollback(fmt.Errorf("adding bypass route %s: %w", p, err))
		}
		h.installed = append(h.installed, r)
	}

	return h, nil
}

// captureDefault finds the current default route (gateway + interface)
// before the tunnel diverts anything.
func captureDefault() (netip.Addr, int, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("listing routes: %w", err)
	}

	var best *netlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Gw == nil || r.Dst == nil {
			continue
		}
		if r.Dst.String() != "0.0.0.0/0" && r.Dst.String() != "::/0" {
			continue
		}
		if r.Table != 0 && r.Table != 254 { // 254 = main
			continue
		}
		if best == nil || r.Priority < best.Priority {
			best = r
		}
	}
	if best == nil {
		return netip.Addr{}, 0, fmt.Errorf("no default route found (is the network up?)")
	}
	gw, ok := netip.AddrFromSlice(best.Gw)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("gateway %v is not an IP", best.Gw)
	}
	return gw.Unmap(), best.LinkIndex, nil
}

// prefixIPNet converts to netlink's *net.IPNet form.
func prefixIPNet(p netip.Prefix) *net.IPNet {
	np := p.Masked()
	return &net.IPNet{
		IP:   np.Addr().AsSlice(),
		Mask: net.CIDRMask(np.Bits(), np.Addr().BitLen()),
	}
}
