package warp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeTeam(t *testing.T) {
	cases := map[string]string{
		"mycompany":                          "mycompany",
		"MyCompany":                          "mycompany",
		"mycompany.cloudflareaccess.com":     "mycompany",
		"https://mycompany.cloudflareaccess.com": "mycompany",
		"https://my-team.cloudflareaccess.com/warp": "my-team",
		"my-company-1": "my-company-1",
	}
	for in, want := range cases {
		got, err := NormalizeTeam(in)
		if err != nil {
			t.Errorf("NormalizeTeam(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeTeam(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "  ", "https://", "my_company", "-lead", "trail-", "a..b"} {
		if _, err := NormalizeTeam(bad); err == nil {
			t.Errorf("NormalizeTeam(%q) should fail", bad)
		}
	}
}

func TestParseTeamToken(t *testing.T) {
	raw := "eyJhbGciOiJIUzI1NiJ9.abc.def"
	cases := map[string]string{
		raw: raw,
		"com.cloudflare.warp://mycompany.cloudflareaccess.com/auth?token=" + raw: raw,
		"https://mycompany.cloudflareaccess.com/warp-d/capture?token=" + raw:      raw,
		"https://mycompany.cloudflareaccess.com/x?token=" + raw + "&other=1":      raw,
		"  " + raw + "  ": raw,
	}
	for in, want := range cases {
		got, err := ParseTeamToken(in)
		if err != nil {
			t.Errorf("ParseTeamToken(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTeamToken(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseTeamToken("   "); err == nil {
		t.Error("empty token should fail")
	}
}

func TestEndpointHost(t *testing.T) {
	cases := map[string]string{
		"162.159.192.10:0":    "162.159.192.10",
		"162.159.192.10":      "162.159.192.10",
		"[2606:4700:d0::a29f:c001]:0": "2606:4700:d0::a29f:c001",
		"[2606:4700:d0::a29f:c001]":   "2606:4700:d0::a29f:c001",
		"": "",
	}
	for in, want := range cases {
		if got := endpointHost(in); got != want {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePolicyBlockVariants(t *testing.T) {
	// 1. policy at the top level
	topLevel := []byte(`{"id":"dev","policy":{"service_mode_v2":{"mode":"warp"},
		"exclude":[{"address":"10.0.0.0/8","description":"RFC1918"}]}}`)
	block, err := parsePolicyBlock(topLevel)
	if err != nil || block == nil {
		t.Fatalf("top-level policy failed: block=%v err=%v", block, err)
	}
	if len(block.Exclude) != 1 || block.Exclude[0].Address != "10.0.0.0/8" {
		t.Errorf("unexpected exclude list: %+v", block.Exclude)
	}
	if block.ServiceModeV2.Mode != "warp" {
		t.Errorf("unexpected service mode: %+v", block.ServiceModeV2)
	}

	// 2. policy nested under result
	nested := []byte(`{"result":{"policy":{"service_mode":"warp",
		"include":[{"host":"ssh.internal.example"}]}}}`)
	block, err = parsePolicyBlock(nested)
	if err != nil || block == nil {
		t.Fatalf("nested policy failed: block=%v err=%v", block, err)
	}
	if len(block.Include) != 1 || block.Include[0].Host != "ssh.internal.example" {
		t.Errorf("unexpected include list: %+v", block.Include)
	}

	// 3. bare include/exclude at top level
	bare := []byte(`{"exclude":[{"address":"192.168.0.0/16"}]}`)
	block, err = parsePolicyBlock(bare)
	if err != nil || block == nil {
		t.Fatalf("bare policy failed: block=%v err=%v", block, err)
	}
	if len(block.Exclude) != 1 {
		t.Errorf("unexpected exclude list: %+v", block.Exclude)
	}

	// 4. no policy anywhere
	none, err := parsePolicyBlock([]byte(`{"id":"dev"}`))
	if err != nil || none != nil {
		t.Errorf("expected nil block without error, got %v / %v", none, err)
	}

	// 5. invalid JSON
	if _, err := parsePolicyBlock([]byte(`{oops`)); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestRemotePolicyModeDerivation(t *testing.T) {
	p := &RemotePolicy{Available: true, Include: nil, Exclude: []RouteEntry{{Address: "10.0.0.0/8"}}}
	if got := p.EffectiveMode("include"); got != "exclude" {
		t.Errorf("mode should follow remote exclude list, got %q", got)
	}
	p2 := &RemotePolicy{Available: true, Include: []RouteEntry{{Address: "10.0.0.0/8"}}}
	if got := p2.EffectiveMode("exclude"); got != "include" {
		t.Errorf("mode should follow remote include list, got %q", got)
	}
	unavailable := &RemotePolicy{Available: false}
	if got := unavailable.EffectiveMode("include"); got != "include" {
		t.Errorf("unavailable policy should fall back to local mode, got %q", got)
	}
	if got := (*RemotePolicy)(nil).EffectiveMode(""); got != "exclude" {
		t.Errorf("nil policy should fall back to exclude, got %q", got)
	}
}

func TestFetchRemotePolicyToleratesShapes(t *testing.T) {
	// Guard the JSON tags used by policyBlock against accidental renames.
	raw := `{"policy":{"include":[{"address":"10.0.0.0/8","description":"d"}],"exclude":[],"service_mode_v2":{"mode":"warp"}}}`
	var payload policyPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Policy == nil || len(payload.Policy.Include) != 1 {
		t.Fatalf("policy unmarshal mismatch: %+v", payload)
	}
	if payload.Policy.Include[0].Description != "d" {
		t.Errorf("description lost: %+v", payload.Policy.Include[0])
	}
	if !strings.Contains(payload.Policy.ServiceModeV2.Mode, "warp") {
		t.Errorf("service mode lost: %+v", payload.Policy.ServiceModeV2)
	}
}
