// Package settings persists warpalt's *local* configuration: the mode used
// when no organization policy can be retrieved, and the routes the user
// explicitly asked to send through the tunnel on top of organization policy.
package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"warpalt/internal/warp"
)

// Settings is the local (non-organization) configuration.
type Settings struct {
	// LocalMode is the split-tunnel mode used only when the organization's
	// remote policy cannot be retrieved: "exclude" (default) or "include".
	LocalMode string `json:"localMode"`
	// LocalRoutes are entries the user added locally; they always mean
	// "route through the tunnel" and are layered on top of organization
	// policy, never removing anything the organization configured.
	LocalRoutes []string `json:"localRoutes"`
}

func path() (string, error) {
	dir, err := warp.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// Load reads the settings file, returning defaults when absent.
func Load() *Settings {
	s := &Settings{LocalMode: "exclude"}
	p, err := path()
	if err != nil {
		return s
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return s
	}
	var loaded Settings
	if err := json.Unmarshal(data, &loaded); err != nil {
		return s
	}
	if loaded.LocalMode == "include" || loaded.LocalMode == "exclude" {
		s.LocalMode = loaded.LocalMode
	}
	s.LocalRoutes = loaded.LocalRoutes
	return s
}

// Save writes the settings file.
func (s *Settings) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return err
	}
	return nil
}

// AddLocalRoute appends an entry (deduplicated) and persists.
func (s *Settings) AddLocalRoute(value string) error {
	for _, existing := range s.LocalRoutes {
		if existing == value {
			return errors.New("that route already exists")
		}
	}
	s.LocalRoutes = append(s.LocalRoutes, value)
	return s.Save()
}

// RemoveLocalRoute drops an entry and persists.
func (s *Settings) RemoveLocalRoute(value string) error {
	out := s.LocalRoutes[:0]
	found := false
	for _, existing := range s.LocalRoutes {
		if existing == value {
			found = true
			continue
		}
		out = append(out, existing)
	}
	if !found {
		return errors.New("route not found")
	}
	s.LocalRoutes = out
	return s.Save()
}
