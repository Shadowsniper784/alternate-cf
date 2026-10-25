package app

import (
	"testing"
)

func TestValidateEntry(t *testing.T) {
	good := []string{
		"10.0.3.1",
		"10.0.3.0/24",
		"::1",
		"2001:db8::/32",
		"ssh.internal.example",
		"host-1.example.com",
	}
	for _, v := range good {
		if err := validateEntry(v); err != nil {
			t.Errorf("validateEntry(%q) = %v, want nil", v, err)
		}
	}

	bad := []string{
		"",
		"10.0.3.0/33",
		"not a host!",
		".leading",
		"trailing.-",
		"10.0.3.1;rm -rf /",
	}
	for _, v := range bad {
		if err := validateEntry(v); err == nil {
			t.Errorf("validateEntry(%q) should fail", v)
		}
	}
}

func TestResolveValuesAddresses(t *testing.T) {
	// With resolve=false hostnames are skipped, addresses/prefixes parsed.
	in := []string{"10.0.3.1", "172.20.0.0/16", "2001:db8::1", "some.host.example"}
	got, warnings := resolveValues(in, false)

	want := map[string]bool{
		"10.0.3.1/32":       true,
		"172.20.0.0/16":     true,
		"2001:db8::1/128":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("resolveValues = %v, want %d entries", got, len(want))
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Errorf("unexpected prefix %s", p)
		}
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected without resolution: %v", warnings)
	}
}

func TestResolveValuesDedupAndMask(t *testing.T) {
	in := []string{"10.0.3.7", "10.0.3.7", "10.0.3.0/24", "10.0.3.9"}
	got, _ := resolveValues(in, false)
	if len(got) != 3 {
		t.Errorf("expected 3 unique entries, got %v", got)
	}
}

func TestKindOf(t *testing.T) {
	if kindOf("10.0.3.1") != "address" || kindOf("10.0.0.0/8") != "address" || kindOf("2001:db8::/32") != "address" {
		t.Error("IPs/CIDRs should be kind address")
	}
	if kindOf("ssh.internal.example") != "host" {
		t.Error("hostnames should be kind host")
	}
}

func TestDefaultExclusionsCoverRFC1918(t *testing.T) {
	list := defaultExclusions()
	found := map[string]bool{}
	for _, v := range list {
		found[v] = true
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if !found[want] {
			t.Errorf("fallback exclusions missing %s", want)
		}
	}
}
