package routes

import (
	"net/netip"
	"reflect"
	"testing"
)

func prefixes(t *testing.T, in ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func contains(list []netip.Prefix, p string) bool {
	want := netip.MustParsePrefix(p)
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

// TestBuildKeepsLinkLocalOutOfTunnel guards the fix for the Windows log
// flood: LLMNR/NetBIOS/SSDP/MLD travel with TTL 1, connect-ip refuses such
// packets, and they can never work past the local link. They must always be
// bypassed, whatever the organization profile asks for.
func TestBuildKeepsLinkLocalOutOfTunnel(t *testing.T) {
	endpoint := netip.MustParseAddr("162.159.192.10")
	// A hostile profile that asks to tunnel the link-local scopes.
	org := prefixes(t, "224.0.0.0/4", "169.254.0.0/16", "ff00::/8")
	wantBypass := []string{
		"224.0.0.0/4",
		"255.255.255.255/32",
		"169.254.0.0/16",
		"ff00::/8",
		"fe80::/10",
	}
	for _, mode := range []string{"exclude", "include"} {
		plan := Build(mode, org, nil, endpoint)
		for _, p := range wantBypass {
			if !contains(plan.Bypass, p) {
				t.Errorf("%s mode: %s not in bypass list: %v", mode, p, plan.Bypass)
			}
			if contains(plan.ViaTunnel, p) {
				t.Errorf("%s mode: %s must not be tunneled: %v", mode, p, plan.ViaTunnel)
			}
		}
	}
}

func TestBuildExcludeMode(t *testing.T) {
	endpoint := netip.MustParseAddr("162.159.192.10")
	org := prefixes(t, "10.0.0.0/8", "192.168.0.0/16")
	local := prefixes(t, "10.0.3.1/32")

	plan := Build("exclude", org, local, endpoint)

	// Half-default routes divert the default route through the tunnel.
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if !contains(plan.ViaTunnel, p) {
			t.Errorf("exclude mode missing half-default route %s (got %v)", p, plan.ViaTunnel)
		}
	}
	// Organization exclusions bypass the tunnel.
	if !contains(plan.Bypass, "10.0.0.0/8") || !contains(plan.Bypass, "192.168.0.0/16") {
		t.Errorf("org exclusions not in bypass list: %v", plan.Bypass)
	}
	// The MASQUE endpoint always bypasses.
	if !contains(plan.Bypass, endpoint.String()+"/32") {
		t.Errorf("endpoint not in bypass list: %v", plan.Bypass)
	}
	// Local additions tunnel - and being /32 they outrank the org's /8
	// bypass, which is exactly the documented override semantics.
	if !contains(plan.ViaTunnel, "10.0.3.1/32") {
		t.Errorf("local route not in tunnel list: %v", plan.ViaTunnel)
	}
	if contains(plan.Bypass, "10.0.3.1/32") {
		t.Errorf("local route must not be in bypass list: %v", plan.Bypass)
	}
	// The user's own default route is never deleted: we only add /1s.
	for _, p := range plan.ViaTunnel {
		if p.Bits() == 0 {
			t.Errorf("plan must not install a full default route, found %s", p)
		}
	}
}

func TestBuildIncludeMode(t *testing.T) {
	endpoint := netip.MustParseAddr("162.159.192.10")
	org := prefixes(t, "10.0.3.0/24")
	local := prefixes(t, "172.20.0.0/16")

	plan := Build("include", org, local, endpoint)

	if contains(plan.ViaTunnel, "0.0.0.0/1") {
		t.Errorf("include mode must not divert the default route: %v", plan.ViaTunnel)
	}
	if !contains(plan.ViaTunnel, "10.0.3.0/24") || !contains(plan.ViaTunnel, "172.20.0.0/16") {
		t.Errorf("include mode should tunnel org + local entries: %v", plan.ViaTunnel)
	}
	if !contains(plan.Bypass, endpoint.String()+"/32") {
		t.Errorf("endpoint must bypass in include mode too: %v", plan.Bypass)
	}
}

func TestBuildDeduplicates(t *testing.T) {
	endpoint := netip.MustParseAddr("162.159.192.10")
	org := prefixes(t, "10.0.0.0/8", "10.0.0.0/8")

	plan := Build("include", org, nil, endpoint)

	count := 0
	for _, p := range plan.ViaTunnel {
		if p.String() == "10.0.0.0/8" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate org entries not deduped: %v", plan.ViaTunnel)
	}
}

func TestBuildEndpointOverlapsOrgInclude(t *testing.T) {
	// When the org includes the endpoint's own range (include mode), the
	// endpoint /32 must still bypass so the transport never enters itself.
	endpoint := netip.MustParseAddr("162.159.192.10")
	org := prefixes(t, "162.159.192.0/24")

	plan := Build("include", org, nil, endpoint)

	if contains(plan.ViaTunnel, endpoint.String()+"/32") {
		t.Errorf("endpoint must not be routed into the tunnel: %v", plan.ViaTunnel)
	}
	if !contains(plan.Bypass, endpoint.String()+"/32") {
		t.Errorf("endpoint /32 missing from bypass: %v", plan.Bypass)
	}
}

func TestConflicts(t *testing.T) {
	org := prefixes(t, "10.0.0.0/8")
	local := prefixes(t, "10.0.3.1/32", "172.20.0.0/16")

	got := Conflicts(org, local)
	if len(got) != 1 {
		t.Fatalf("expected one conflict, got %v", got)
	}
	if got[0][0].String() != "10.0.0.0/8" || got[0][1].String() != "10.0.3.1/32" {
		t.Errorf("unexpected conflict pair: %v", got[0])
	}
}

func TestBuildMaskNormalizesHostBits(t *testing.T) {
	endpoint := netip.MustParseAddr("162.159.192.10")
	local := []netip.Prefix{netip.MustParsePrefix("10.0.3.7/24")}

	plan := Build("include", nil, local, endpoint)

	if !contains(plan.ViaTunnel, "10.0.3.0/24") {
		t.Errorf("host bits should be masked away: %v", plan.ViaTunnel)
	}
}

func TestDedupeRemovesInvalid(t *testing.T) {
	in := []netip.Prefix{{}, netip.MustParsePrefix("10.0.0.0/8")}
	out := dedupe(in)
	if !reflect.DeepEqual(out, prefixes(t, "10.0.0.0/8")) {
		t.Errorf("dedupe = %v", out)
	}
}
