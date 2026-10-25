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

// Apply installs the plan: capture the current default route first, then add
// the tunnel routes on the TUN device and the bypass routes on the original
// interface via the original gateway. If any install fails, everything added
// so far is rolled back.
func Apply(plan Plan, tunIface string) (*Handle, error) {
	ifi, err := net.InterfaceByName(tunIface)
	if err != nil {
		return nil, fmt.Errorf("finding tunnel interface %q: %w", tunIface, err)
	}
	tunLUID, err := winipcfg.LUIDFromIndex(uint32(ifi.Index))
	if err != nil {
		return nil, fmt.Errorf("resolving tunnel interface LUID: %w", err)
	}

	gw, origLUID, err := captureDefault()
	if err != nil {
		return nil, err
	}

	h := &Handle{}
	rollback := func(cause error) (*Handle, error) {
		_ = h.Remove()
		return nil, cause
	}

	for _, p := range plan.ViaTunnel {
		if err := tunLUID.AddRoute(p, netip.Addr{}, 1); err != nil {
			return rollback(fmt.Errorf("adding tunnel route %s: %w", p, err))
		}
		h.installed = append(h.installed, installedRoute{luid: tunLUID, prefix: p})
	}

	for _, p := range plan.Bypass {
		if !gw.IsValid() {
			return rollback(fmt.Errorf("no default route to install bypass %s", p))
		}
		if err := origLUID.AddRoute(p, gw, 1); err != nil {
			return rollback(fmt.Errorf("adding bypass route %s: %w", p, err))
		}
		h.installed = append(h.installed, installedRoute{luid: origLUID, prefix: p, nextHop: gw})
	}

	return h, nil
}

// captureDefault finds the active default route (gateway + interface) before
// the tunnel diverts anything. IPv4 is preferred; IPv6 is used as a fallback.
func captureDefault() (netip.Addr, winipcfg.LUID, error) {
	families := []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6}

	var bestGW netip.Addr
	var bestLUID winipcfg.LUID
	var bestMetric uint32

	for _, fam := range families {
		rows, err := winipcfg.GetIPForwardTable2(fam)
		if err != nil {
			continue
		}
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
			if !bestGW.IsValid() || row.Metric < bestMetric {
				bestGW = gw
				bestLUID = row.InterfaceLUID
				bestMetric = row.Metric
			}
		}
		if bestGW.IsValid() {
			return bestGW, bestLUID, nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("no default route found (is the network up?)")
}
