package warp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity holds the enrollment identity.
type Identity struct {
	Team           string `json:"team"`
	Key            string `json:"key"`
	Token          string `json:"token"`
	Secret         string `json:"secret"`
	APIURL         string `json:"apiUrl"`
	GatewayURL     string `json:"gatewayUrl"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
	DeviceID       string `json:"deviceId,omitempty"`
	AccessToken    string `json:"accessToken,omitempty"`
	PrivateKey     string `json:"privateKey,omitempty"`
	EndpointV4     string `json:"endpointV4,omitempty"`
	EndpointV6     string `json:"endpointV6,omitempty"`
	EndpointPubKey string `json:"endpointPubKey,omitempty"`
	Created        string `json:"created,omitempty"`
	DeviceName     string `json:"deviceName,omitempty"`
	Protocol       string `json:"protocol,omitempty"`  // "wireguard" or "masque"
	WgProfile      string `json:"wgProfile,omitempty"` // WireGuard profile config (base64-encoded)
}

func (id *Identity) Validate() error {
	if id.Team == "" {
		return fmt.Errorf("team is required")
	}
	if id.PrivateKey == "" {
		return fmt.Errorf("device private key is required")
	}
	if id.EndpointPubKey == "" {
		return fmt.Errorf("endpoint public key is required")
	}
	if id.EndpointV4 == "" && id.EndpointV6 == "" {
		return fmt.Errorf("MASQUE endpoint is required")
	}
	if id.IPv4 == "" && id.IPv6 == "" {
		return fmt.Errorf("tunnel IP address is required")
	}
	return nil
}

// Save persists the identity into the user config directory.
func (id *Identity) Save() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating identity directory: %w", err)
	}
	b, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadIdentity loads the stored identity from the config directory. It
// returns ErrNoIdentity when no saved identity exists.
func LoadIdentity() (*Identity, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoIdentity
		}
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	return &id, nil
}

// Delete removes the stored identity and its config directory.
func (id *Identity) Delete() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(filepath.Dir(path))
}

var (
	ErrNoIdentity = fmt.Errorf("no saved identity")
)

// Dir returns warpalt's per-user configuration directory. It respects
// XDG_CONFIG_HOME on Linux (so tests can redirect it) and %AppData% on
// Windows.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "warpalt"), nil
}

func configPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.json"), nil
}
