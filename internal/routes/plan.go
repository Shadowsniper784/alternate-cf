// Package routes computes and applies the OS routing table changes that
// implement warpalt's split tunnel.
//
// The organization's remote policy is the base configuration; local entries
// are additive and, being more specific than the base entries, always win for
// exactly the prefixes the user named. Nothing the organization listed is
// removed: an override only happens because the user added a more specific
// prefix on top.
package routes

import "net/netip"

// Plan describes the routing table changes needed to bring the split tunnel
// up. It is pure data: platform appliers (linux/windows) install it.
type Plan struct {
	// Mode is the effective split-tunnel mode ("include"/"exclude").
	Mode string
	// ViaTunnel is installed on the TUN interface: traffic to these
	// destinations enters the tunnel.
	ViaTunnel []netip.Prefix
	// Bypass is installed on the original default interface via the original
	// gateway: traffic to these destinations must leave the machine directly
	// (organization exclusions and the MASQUE endpoint itself).
	Bypass []netip.Prefix
}

// Build computes the plan.
//
//	exclude: everything tunnels (half-default routes so the user's own default
//	         route is never deleted), organization exclusions and the endpoint
//	         bypass, local entries tunnel through their more specific prefixes.
//	include: only organization inclusions + local entries tunnel; nothing else
//	         is touched.
func Build(mode string, org, local []netip.Prefix, endpoint netip.Addr) Plan {
	p := Plan{Mode: mode}

	if mode == "exclude" {
		// Two /1 routes cover the default space while staying less specific
		// than any organization exclusion (/8, /16, ...), so the original
		// default route can stay in place untouched.
		p.ViaTunnel = append(p.ViaTunnel,
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		)
		p.Bypass = append(p.Bypass, org...)
	} else {
		p.ViaTunnel = append(p.ViaTunnel, org...)
	}

	// Local additions always mean "send this through the tunnel".
	p.ViaTunnel = append(p.ViaTunnel, local...)

	// The transport endpoint must never enter its own tunnel.
	if endpoint.IsValid() {
		p.Bypass = append(p.Bypass, netip.PrefixFrom(endpoint, endpoint.BitLen()))
	}

	p.ViaTunnel = dedupe(p.ViaTunnel)
	p.Bypass = dedupe(p.Bypass)
	return p
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := in[:0]
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// Conflicts reports, for the UI, local entries whose destination is already
// covered by an organization exclusion - the local entry still wins because
// it is more specific, but the user should know it overrides an org setting.
func Conflicts(org, local []netip.Prefix) [][2]netip.Prefix {
	var out [][2]netip.Prefix
	for _, l := range local {
		for _, o := range org {
			if o.Overlaps(l) && o != l {
				out = append(out, [2]netip.Prefix{o, l})
				break
			}
		}
	}
	return out
}
