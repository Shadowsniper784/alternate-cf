//go:build linux

package routes

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

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
		err := netlink.RouteDel(&r)
		if err != nil &&
			!errors.Is(err, syscall.ESRCH) &&
			!errors.Is(err, syscall.ENOENT) &&
			!errors.Is(err, syscall.EINVAL) &&
			firstErr == nil {
			firstErr = err
		}
	}
	h.installed = nil
	return firstErr
}

// Apply installs the plan: tunnel routes on the TUN device, bypass routes on
// the original interface via the original gateway. The machine's own default
// route is never removed. Any partial failure rolls everything back.
func Apply(plan Plan, tunIface string) (*Handle, error) {
	link, err := netlink.LinkByName(tunIface)
	if err != nil {
		return nil, fmt.Errorf("locating tunnel link %q: %w", tunIface, err)
	}
	ifIndex := link.Attrs().Index

	h := &Handle{}
	rollback := func(cause error) (*Handle, error) {
		_ = h.Remove()
		return nil, cause
	}

	// Resolve where each bypass destination actually egresses *before* the
	// tunnel routes exist. The kernel's own decision (RouteGet) honours policy
	// routing tables, VPN interfaces and marks; reading "the lowest metric
	// default in main" does not, and can send the MASQUE transport down a
	// different link than the one every other socket uses.
	type bypassRoute struct {
		prefix    netip.Prefix
		gw        netip.Addr // invalid means on-link (no gateway)
		linkIndex int
	}
	var bypasses []bypassRoute
	for _, p := range plan.Bypass {
		gw, idx, err := egressFor(p.Addr(), ifIndex)
		if err != nil {
			// No usable path in this family: nothing to bypass through, so
			// skip instead of failing the whole connect.
			continue
		}
		bypasses = append(bypasses, bypassRoute{prefix: p, gw: gw, linkIndex: idx})
	}

	for _, p := range plan.ViaTunnel {
		if p.Bits() == 0 {
			// The plan uses the two /1 prefixes on purpose; a full default
			// would delete the user's route.
			continue
		}
		r := netlink.Route{
			Dst:       prefixIPNet(p),
			LinkIndex: ifIndex,
			Scope:     netlink.SCOPE_LINK,
			Priority:  50,
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return rollback(fmt.Errorf("adding tunnel route %s: %w", p, err))
		}
		h.installed = append(h.installed, r)
	}

	for _, b := range bypasses {
		r := netlink.Route{
			Dst:       prefixIPNet(b.prefix),
			LinkIndex: b.linkIndex,
			Priority:  50,
		}
		// Multicast, broadcast and link-local scopes are never routed: keep
		// them on-link on the egress interface instead of via a gateway.
		if b.gw.IsValid() && !isLinkLocalScope(b.prefix) {
			r.Gw = b.gw.AsSlice()
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return rollback(fmt.Errorf("adding bypass route %s: %w", b.prefix, err))
		}
		h.installed = append(h.installed, r)
	}

	return h, nil
}

// egressFor reports how the kernel would send traffic to dst right now: the
// gateway (invalid when the route is on-link) and the outgoing link. The
// tunnel link is rejected so a stale tunnel route can never become its own
// bypass; in that case we fall back to the active default route.
func egressFor(dst netip.Addr, tunIndex int) (netip.Addr, int, error) {
	routes, err := netlink.RouteGet(dst.AsSlice())
	if err == nil && len(routes) > 0 {
		r := routes[0]
		if r.LinkIndex != 0 && r.LinkIndex != tunIndex {
			if r.Gw == nil {
				// On-link route (typical for a VPN point-to-point device):
				// install it without a gateway so the path is preserved.
				return netip.Addr{}, r.LinkIndex, nil
			}
			if gw, ok := netip.AddrFromSlice(r.Gw); ok && gw.IsValid() {
				return gw.Unmap(), r.LinkIndex, nil
			}
		}
	}
	return captureDefaultFor(dst.Is4())
}

// captureDefaultFor finds the active default route (gateway + link index) for
// one address family before the tunnel diverts anything.
func captureDefaultFor(v4 bool) (netip.Addr, int, error) {
	family := netlink.FAMILY_V4
	if !v4 {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("listing routes: %w", err)
	}

	var best *netlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Dst == nil || r.Gw == nil || r.LinkIndex == 0 {
			continue
		}
		ones, _ := r.Dst.Mask.Size()
		if ones != 0 { // only the default route (prefix length 0)
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
		return netip.Addr{}, 0, fmt.Errorf("no default route found")
	}
	gw, ok := netip.AddrFromSlice(best.Gw)
	if !ok || gw.IsUnspecified() {
		return netip.Addr{}, 0, fmt.Errorf("gateway %v is not a usable IP", best.Gw)
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
