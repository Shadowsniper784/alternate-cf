package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"warpalt/internal/routes"
	"warpalt/internal/settings"
	"warpalt/internal/warp"
)

// Entry is one split-tunnel row shown by the UI.
type Entry struct {
	Value       string `json:"value"`
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
}

// Conflict is a local entry that overlaps an organization entry.
type Conflict struct {
	Org   string `json:"org"`
	Local string `json:"local"`
}

// SplitView is the complete split-tunnel screen state.
type SplitView struct {
	Mode            string     `json:"mode"`
	ModeSource      string     `json:"modeSource"`
	RemoteAvailable bool       `json:"remoteAvailable"`
	RemoteError     string     `json:"remoteError,omitempty"`
	RemoteNote      string     `json:"remoteNote,omitempty"`
	OrgEntries      []Entry    `json:"orgEntries"`
	LocalEntries    []Entry    `json:"localEntries"`
	Conflicts       []Conflict `json:"conflicts"`
	LocalMode       string     `json:"localMode"`
	Connected       bool       `json:"connected"`
	Warnings        []string   `json:"warnings,omitempty"`
}

type resolution struct {
	prefixes []netip.Prefix
	err      error
	at       time.Time
}

const (
	resolveTTL     = 5 * time.Minute
	resolveFailTTL = 30 * time.Second
	resolveTimeout = 3 * time.Second
)

// buildSplitView assembles the view without blocking on a policy refresh.
func (a *Application) buildSplitView() SplitView {
	local := settings.Load()
	status := a.GetStatus()

	view := SplitView{
		Mode:         local.LocalMode,
		ModeSource:   "local",
		LocalMode:    local.LocalMode,
		Connected:    isRunning(status.State),
		OrgEntries:   []Entry{},
		LocalEntries: []Entry{},
		Conflicts:    []Conflict{},
		Warnings:     []string{},
	}

	if id, err := warp.LoadIdentity(); err != nil || id.Validate() != nil {
		view.Warnings = append(view.Warnings, "Not enrolled yet. Register this device to see organization settings.")
		return view
	}

	policy := a.remotePolicy(false)
	view.RemoteAvailable = policy.Available
	view.RemoteError = policy.Error
	view.RemoteNote = policy.Describe()

	mode := policy.EffectiveMode(local.LocalMode)
	view.Mode = mode
	if policy.Available && (policy.Mode != "" || len(policy.Include)+len(policy.Exclude) > 0) {
		view.ModeSource = "organization"
	}

	var orgValues, localValues []string
	for _, e := range policy.OrgEntries(mode) {
		v := strings.TrimSpace(e.Value())
		if v == "" {
			continue
		}
		view.OrgEntries = append(view.OrgEntries, Entry{
			Value:       v,
			Kind:        kindOfEntry(e),
			Description: e.Description,
		})
		orgValues = append(orgValues, v)
	}
	for _, v := range local.LocalRoutes {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		view.LocalEntries = append(view.LocalEntries, Entry{Value: v, Kind: kindOf(v)})
		localValues = append(localValues, v)
	}

	orgPrefixes, orgWarnings := a.resolveAll(orgValues)
	localPrefixes, localWarnings := a.resolveAll(localValues)
	view.Warnings = append(view.Warnings, orgWarnings...)
	view.Warnings = append(view.Warnings, localWarnings...)

	for _, pair := range routes.Conflicts(orgPrefixes, localPrefixes) {
		view.Conflicts = append(view.Conflicts, Conflict{
			Org:   pair[0].String(),
			Local: pair[1].String(),
		})
	}
	return view
}

// defaultExclusions is the conservative fallback used only when the
// organization profile could not be retrieved.
func defaultExclusions() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
}

func isRunning(state string) bool {
	switch state {
	case "connecting", "connected", "reconnecting":
		return true
	default:
		return false
	}
}

func kindOfEntry(e warp.RouteEntry) string {
	if e.IsAddress() {
		return "ip"
	}
	return "host"
}

func kindOf(value string) string {
	if _, ok := directPrefix(value); ok {
		return "ip"
	}
	return "host"
}

// directPrefix parses a CIDR or a bare IP without touching DNS.
func directPrefix(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// resolveAll resolves every entry, returning warnings for entries that could
// not be used. Resolution failures never fail the whole view.
func (a *Application) resolveAll(values []string) ([]netip.Prefix, []string) {
	var prefixes []netip.Prefix
	var warnings []string
	for _, value := range values {
		if p, ok := directPrefix(value); ok {
			prefixes = append(prefixes, p)
			continue
		}
		got, err := a.resolveHost(value)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", value, err))
			continue
		}
		prefixes = append(prefixes, got...)
	}
	return prefixes, warnings
}

func (a *Application) resolveHost(value string) ([]netip.Prefix, error) {
	host := strings.TrimSpace(value)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	now := time.Now()

	a.resMu.Lock()
	if r, ok := a.resolved[host]; ok {
		ttl := resolveTTL
		if r.err != nil {
			ttl = resolveFailTTL
		}
		if now.Sub(r.at) < ttl {
			a.resMu.Unlock()
			return r.prefixes, r.err
		}
	}
	a.resMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	var out []netip.Prefix
	if err == nil {
		seen := make(map[netip.Prefix]struct{}, len(addrs))
		for _, addr := range addrs {
			p := netip.PrefixFrom(addr, addr.BitLen())
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
		if len(out) == 0 {
			err = errors.New("no addresses returned")
		}
	}

	a.resMu.Lock()
	if a.resolved == nil {
		a.resolved = make(map[string]resolution)
	}
	a.resolved[host] = resolution{prefixes: out, err: err, at: now}
	a.resMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("could not resolve: %w", err)
	}
	return out, nil
}

// validateEntry accepts an IP, CIDR or syntactically valid hostname. It does
// not require DNS to answer, so adding an entry works offline.
func validateEntry(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("enter an IP address, CIDR or hostname")
	}
	if _, ok := directPrefix(value); ok {
		return nil
	}
	host := value
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.ContainsAny(host, " /\\") || len(host) > 253 {
		return fmt.Errorf("%q is not a valid IP, CIDR or hostname", value)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q is not a valid hostname", value)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%q is not a valid hostname", value)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("%q is not a valid hostname", value)
		}
	}
	return nil
}

// buildPlan derives the route plan and endpoint for one connect or update.
func (a *Application) buildPlan(id *warp.Identity, policy *warp.RemotePolicy, local *settings.Settings) (routes.Plan, string, string, []string) {
	mode := policy.EffectiveMode(local.LocalMode)

	var orgValues []string
	for _, e := range policy.OrgEntries(mode) {
		if v := strings.TrimSpace(e.Value()); v != "" {
			orgValues = append(orgValues, v)
		}
	}
	if !policy.Available && mode == "exclude" {
		// Without an organization profile, keep the local LAN reachable the
		// way Cloudflare's default profile does instead of dragging RFC1918
		// traffic through the tunnel.
		orgValues = append(orgValues, defaultExclusions()...)
	}
	orgPrefixes, orgWarnings := a.resolveAll(orgValues)
	localPrefixes, localWarnings := a.resolveAll(local.LocalRoutes)

	host := id.EndpointV4
	if host == "" {
		host = id.EndpointV6
	}
	endpoint, err := netip.ParseAddr(host)
	if err != nil {
		return routes.Plan{}, mode, "", []string{fmt.Sprintf("invalid MASQUE endpoint %q", host)}
	}

	plan := routes.Build(mode, orgPrefixes, localPrefixes, endpoint)
	warnings := append(orgWarnings, localWarnings...)
	return plan, mode, net.JoinHostPort(endpoint.String(), "443"), warnings
}
