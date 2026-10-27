//go:build windows

package routes

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type installedRoute struct {
	luid    winipcfg.LUID
	prefix  netip.Prefix
	nextHop netip.Addr
}

// Handle represents installed routes that can be removed again.
type Handle struct {
	installed []installedRoute
}

// Remove deletes every route this handle installed (idempotent).
func (h *Handle) Remove() error {
	var firstErr error
	for i := len(h.installed) - 1; i >= 0; i-- {
		r := h.installed[i]
		if err := r.luid.DeleteRoute(r.prefix, r.nextHop); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.installed = nil
	return firstErr
}

// Apply installs the plan: tunnel routes on the Wintun adapter, bypass routes
// on the original interface via the original gateway. The existing default
// route is never removed; the plan uses the /1 prefixes instead.
func Apply(plan Plan, tunIface string) (*Handle, error) {
	ifi, err := net.InterfaceByName(tunIface)
	if err != nil {
		return nil, fmt.Errorf("finding tunnel interface %q: %w", tunIface, err)
	}
	tunLUID, err := winipcfg.LUIDFromIndex(uint32(ifi.Index))
	if err != nil {
		return nil, fmt.Errorf("resolving tunnel interface LUID: %w", err)
	}

	h := &Handle{}
	rollback := func(cause error) (*Handle, error) {
		_ = h.Remove()
		return nil, cause
	}

	for _, p := range plan.ViaTunnel {
		if p.Bits() == 0 {
			continue
		}
		nextHop := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		if err := tunLUID.AddRoute(p.Masked(), nextHop, 1); err != nil {
			return rollback(fmt.Errorf("adding tunnel route %s: %w", p, err))
		}
		h.installed = append(h.installed, installedRoute{luid: tunLUID, prefix: p, nextHop: nextHop})
	}

	// Resolve the real egress for every bypass destination before the tunnel
	// routes exist, so the transport leaves on the interface Windows itself
	// would pick for it rather than whichever interface owns the default.
	type bypassRoute struct {
		prefix  netip.Prefix
		nextHop netip.Addr // invalid means on-link (no gateway)
		luid    winipcfg.LUID
	}
	var bypasses []bypassRoute
	for _, p := range plan.Bypass {
		gw, origLUID, err := egressFor(p.Addr(), tunLUID)
		if err != nil {
			// No route in this family; nothing to bypass through.
			continue
		}
		bypasses = append(bypasses, bypassRoute{prefix: p, nextHop: gw, luid: origLUID})
	}

	for _, b := range bypasses {
		if err := b.luid.AddRoute(b.prefix.Masked(), b.nextHop, 1); err != nil {
			return rollback(fmt.Errorf("adding bypass route %s: %w", b.prefix, err))
		}
		h.installed = append(h.installed, installedRoute{luid: b.luid, prefix: b.prefix, nextHop: b.nextHop})
	}

	return h, nil
}

// egressFor reports the next hop and interface Windows would use for dst,
// preferring the most specific matching route with the lowest metric. The
// tunnel's own LUID is rejected so a stale tunnel route can never become its
// own bypass; when nothing matches we fall back to the active default route.
func egressFor(dst netip.Addr, tunLUID winipcfg.LUID) (netip.Addr, winipcfg.LUID, error) {
	family := winipcfg.AddressFamily(windows.AF_INET6)
	if dst.Is4() {
		family = winipcfg.AddressFamily(windows.AF_INET)
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("reading forward table: %w", err)
	}

	var (
		bestGW     netip.Addr
		bestLUID   winipcfg.LUID
		bestMetric uint32
		bestBits   int
		found      bool
	)
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID == 0 || row.InterfaceLUID == tunLUID {
			continue
		}
		prefix := netip.PrefixFrom(row.DestinationPrefix.RawPrefix.Addr(), int(row.DestinationPrefix.PrefixLength))
		if !prefix.IsValid() || !prefix.Contains(dst) {
			continue
		}
		if !found || row.Metric < bestMetric || (row.Metric == bestMetric && prefix.Bits() > bestBits) {
			gw := row.NextHop.Addr()
			if !gw.IsValid() || gw.IsUnspecified() {
				gw = netip.Addr{} // on-link
			}
			bestGW = gw
			bestLUID = row.InterfaceLUID
			bestMetric = row.Metric
			bestBits = prefix.Bits()
			found = true
		}
	}
	if found {
		return bestGW, bestLUID, nil
	}
	return captureDefaultFor(dst.Is4())
}

// captureDefaultFor finds the active default route (gateway + interface LUID)
// for one address family before the tunnel diverts anything.
func captureDefaultFor(v4 bool) (netip.Addr, winipcfg.LUID, error) {
	family := winipcfg.AddressFamily(windows.AF_INET6)
	if v4 {
		family = winipcfg.AddressFamily(windows.AF_INET)
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("reading forward table: %w", err)
	}

	var bestGW netip.Addr
	var bestLUID winipcfg.LUID
	var bestMetric uint32
	found := false

	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		gw := row.NextHop.Addr()
		if !gw.IsValid() || gw.IsUnspecified() {
			continue
		}
		if row.InterfaceLUID == 0 {
			continue
		}
		if !found || row.Metric < bestMetric {
			bestGW = gw
			bestLUID = row.InterfaceLUID
			bestMetric = row.Metric
			found = true
		}
	}
	if !found {
		return netip.Addr{}, 0, fmt.Errorf("no default route found")
	}
	return bestGW, bestLUID, nil
}
