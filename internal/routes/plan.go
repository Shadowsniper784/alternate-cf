package routes

import (
	"net/netip"
	"sort"
)

// Plan is a set of routes for the WARP tunnel.
//
// ViaTunnel routes are installed on the TUN device. Bypass routes are installed
// on the original interface via the original gateway so that the MASQUE
// transport (and anything the organization excludes) never enters the tunnel.
type Plan struct {
	ViaTunnel []netip.Prefix `json:"viaTunnel"`
	Bypass    []netip.Prefix `json:"bypass"`
}

// Build turns the effective split-tunnel policy into a route plan.
//
// Exclude mode (the default) diverts the default route with the two /1
// prefixes for each family, so the machine's own default route is never
// deleted. Organization entries become bypass routes; local entries are added
// as tunnel routes and, being more specific, win over an organization bypass
// for exactly those addresses.
//
// Include mode only installs the listed routes on the TUN device. The MASQUE
// endpoint is always bypassed in both modes so the transport cannot route into
// itself.
func Build(mode string, org, local []netip.Prefix, endpoint netip.Addr) Plan {
	var plan Plan

	var ep netip.Prefix
	if endpoint.IsValid() {
		ep = netip.PrefixFrom(endpoint, endpoint.BitLen())
		plan.Bypass = append(plan.Bypass, ep)
	}

	if mode == "include" {
		plan.ViaTunnel = append(plan.ViaTunnel, org...)
		plan.ViaTunnel = append(plan.ViaTunnel, local...)
	} else {
		plan.ViaTunnel = append(plan.ViaTunnel,
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		)
		plan.Bypass = append(plan.Bypass, org...)
		plan.ViaTunnel = append(plan.ViaTunnel, local...)
	}

	plan.ViaTunnel = dedupe(plan.ViaTunnel)
	plan.Bypass = dedupe(plan.Bypass)

	if ep.IsValid() {
		// A more specific bypass route wins over an organization prefix that
		// happens to contain the endpoint, but never leave the exact endpoint
		// in the tunnel list.
		plan.ViaTunnel = removePrefix(plan.ViaTunnel, ep)
		plan.Bypass = append(plan.Bypass, ep)
		plan.Bypass = dedupe(plan.Bypass)
	}

	return plan
}

// Conflicts reports local entries that overlap an organization entry. The
// local entry is more specific and therefore wins, but the UI highlights it.
func Conflicts(org, local []netip.Prefix) [][2]netip.Prefix {
	var out [][2]netip.Prefix
	for _, o := range dedupe(org) {
		for _, l := range dedupe(local) {
			if prefixesOverlap(o, l) {
				out = append(out, [2]netip.Prefix{o, l})
			}
		}
	}
	return out
}

// dedupe masks host bits, drops invalid and duplicate prefixes, and returns a
// stable order.
func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr().Is4() != out[j].Addr().Is4() {
			return out[i].Addr().Is4()
		}
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

func removePrefix(in []netip.Prefix, drop netip.Prefix) []netip.Prefix {
	out := in[:0]
	for _, p := range in {
		if p == drop {
			continue
		}
		out = append(out, p)
	}
	return out
}

func prefixesOverlap(a, b netip.Prefix) bool {
	a, b = a.Masked(), b.Masked()
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
