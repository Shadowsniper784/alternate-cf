// Package warp implements the tunnel core of warpalt: device enrollment,
// remote profile retrieval, TUN session management and split-tunnel routes.
//
// The WARP registration, key enrollment and MASQUE transport are provided by
// the MIT-licensed usque project (github.com/Diniboy1123/usque). Small key and
// certificate helpers replicate usque's module-internal helpers - see keys.go.
package warp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is the persisted device registration: everything needed to bring
// the tunnel up without talking to the enrollment API again.
type Identity struct {
	// DeviceName is the name shown in the Zero Trust dashboard.
	DeviceName string `json:"device_name"`
	// Team is the organization subdomain the device enrolled against
	// (e.g. "mycompany" for mycompany.cloudflareaccess.com). Empty means a
	// personal (consumer) registration.
	Team string `json:"team,omitempty"`

	// PrivateKey is the base64-encoded ECDSA P-256 private key used for the
	// MASQUE client certificate.
	PrivateKey string `json:"private_key"`
	// EndpointV4/EndpointV6 are the MASQUE endpoints (bare IPs, no port).
	EndpointV4 string `json:"endpoint_v4"`
	EndpointV6 string `json:"endpoint_v6"`
	// EndpointPubKey is the PEM-encoded endpoint public key we pin.
	EndpointPubKey string `json:"endpoint_pub_key"`

	// DeviceID is the registration id, AccessToken the device bearer token.
	DeviceID    string `json:"id"`
	AccessToken string `json:"access_token"`

	// IPv4/IPv6 are the addresses assigned inside the tunnel.
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`

	Created string `json:"created,omitempty"`
}

// Dir returns the directory holding warpalt's state.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate config dir: %w", err)
	}
	return filepath.Join(base, "warpalt"), nil
}

func identityPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.json"), nil
}

// LoadIdentity returns the saved device identity, or nil when none exists.
func LoadIdentity() (*Identity, error) {
	path, err := identityPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	if id.DeviceID == "" || id.AccessToken == "" {
		return nil, errors.New("identity file is incomplete; re-enroll")
	}
	return &id, nil
}

// Save persists the identity with owner-only permissions (it holds the
// device bearer token).
func (i *Identity) Save() error {
	path, err := identityPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing identity: %w", err)
	}
	return nil
}

// Delete removes the stored identity (log out / re-enroll).
func Delete() error {
	path, err := identityPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
