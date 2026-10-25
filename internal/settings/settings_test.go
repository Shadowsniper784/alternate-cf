package settings

import (
	"testing"
)

func TestSettingsRoundtrip(t *testing.T) {
	// Keep the test hermetic: point the user config dir at a temp dir.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	s := &Settings{LocalMode: "exclude"}
	if err := s.AddLocalRoute("10.0.3.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalRoute("ssh.internal.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalRoute("10.0.3.1"); err == nil {
		t.Error("duplicate route should be rejected")
	}

	loaded := Load()
	if loaded.LocalMode != "exclude" {
		t.Errorf("LocalMode = %q", loaded.LocalMode)
	}
	if len(loaded.LocalRoutes) != 2 {
		t.Fatalf("LocalRoutes = %v", loaded.LocalRoutes)
	}

	if err := loaded.RemoveLocalRoute("10.0.3.1"); err != nil {
		t.Fatal(err)
	}
	if err := loaded.RemoveLocalRoute("nope"); err == nil {
		t.Error("removing a missing route should fail")
	}

	reloaded := Load()
	if len(reloaded.LocalRoutes) != 1 || reloaded.LocalRoutes[0] != "ssh.internal.example" {
		t.Errorf("after removal: %v", reloaded.LocalRoutes)
	}

	reloaded.LocalMode = "include"
	if err := reloaded.Save(); err != nil {
		t.Fatal(err)
	}
	if got := Load(); got.LocalMode != "include" {
		t.Errorf("persisted LocalMode = %q", got.LocalMode)
	}
}

func TestLoadDefaultsWhenMissing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := Load()
	if s.LocalMode != "exclude" {
		t.Errorf("default LocalMode = %q, want exclude", s.LocalMode)
	}
	if len(s.LocalRoutes) != 0 {
		t.Errorf("default LocalRoutes = %v", s.LocalRoutes)
	}
}
