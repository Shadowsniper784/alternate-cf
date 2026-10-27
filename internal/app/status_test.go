package app

import (
	"path/filepath"
	"strings"
	"testing"

	"warpalt/internal/warp"
)

func TestStatusWithoutDaemon(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARPALT_SOCKET", filepath.Join(dir, "missing.sock"))
	t.Setenv("XDG_CONFIG_HOME", dir)

	a := New()
	st := a.GetStatus()
	if st.Enrolled {
		t.Errorf("expected not enrolled, got %+v", st)
	}
	// The enrollment screen should not be covered by a service error before
	// there is anything to connect.
	if st.LastError != "" {
		t.Errorf("unexpected error before enrollment: %q", st.LastError)
	}

	view := a.GetSplit()
	if view.RemoteAvailable {
		t.Errorf("policy should be unavailable: %+v", view)
	}
	if len(view.Warnings) == 0 {
		t.Error("expected an enrollment warning")
	}
	if view.Mode != "exclude" {
		t.Errorf("default mode = %q, want exclude", view.Mode)
	}

	id := &warp.Identity{
		Team:           "example",
		PrivateKey:     "a2V5",
		EndpointPubKey: "cHVi",
		EndpointV4:     "162.159.192.1",
		IPv4:           "172.16.0.2",
		DeviceName:     "test",
	}
	if err := id.Save(); err != nil {
		t.Fatalf("saving test identity: %v", err)
	}
	st = a.GetStatus()
	if !st.Enrolled {
		t.Fatalf("local identity not reported: %+v", st)
	}
	if !strings.Contains(st.LastError, "warpaltd") {
		t.Errorf("error should name the service: %q", st.LastError)
	}
}
