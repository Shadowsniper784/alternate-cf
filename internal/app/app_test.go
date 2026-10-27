package app

import "testing"

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

func TestDirectPrefix(t *testing.T) {
	cases := map[string]string{
		"10.0.3.1":      "10.0.3.1/32",
		"10.0.3.0/24":   "10.0.3.0/24",
		"2001:db8::1":   "2001:db8::1/128",
		"2001:db8::/32": "2001:db8::/32",
	}
	for in, want := range cases {
		got, ok := directPrefix(in)
		if !ok {
			t.Errorf("directPrefix(%q) should parse", in)
			continue
		}
		if got.String() != want {
			t.Errorf("directPrefix(%q) = %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{"", "ssh.internal.example", "999.1.1.1", "10.0.0.0/33"} {
		if _, ok := directPrefix(in); ok {
			t.Errorf("directPrefix(%q) should not parse", in)
		}
	}
}

func TestKindOf(t *testing.T) {
	if kindOf("10.0.3.1") != "ip" || kindOf("10.0.0.0/8") != "ip" || kindOf("2001:db8::/32") != "ip" {
		t.Error("IPs/CIDRs should be kind ip")
	}
	if kindOf("ssh.internal.example") != "host" {
		t.Error("hostnames should be kind host")
	}
}

func TestDefaultExclusionsCoverRFC1918(t *testing.T) {
	found := map[string]bool{}
	for _, v := range defaultExclusions() {
		found[v] = true
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if !found[want] {
			t.Errorf("fallback exclusions missing %s", want)
		}
	}
}
