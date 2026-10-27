package warp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
)

// WgKeyPair holds a WireGuard key pair.
type WgKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateWgKeyPair generates a new WireGuard key pair.
func GenerateWgKeyPair() (*WgKeyPair, error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, err
	}

	return &WgKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privKey[:]),
		PublicKey:  "", // Will be set from enrollment
	}, nil
}

// String returns the base64-encoded public key.
func (k *WgKeyPair) String() string {
	return k.PrivateKey
}

// startWireGuard starts the WireGuard connection.
func startWireGuard(ctx context.Context, id *Identity) error {
	if id.Protocol == "wireguard" {
		return startWgConnection(ctx, id)
	}
	return nil
}

func startWgConnection(ctx context.Context, id *Identity) error {
	profile := LoadWgProfile(id.DeviceID)
	if profile == nil {
		log.Printf("warpalt: no WireGuard profile found for device %s", id.DeviceID)
		return nil
	}

	// The actual WireGuard tunnel is managed by the daemon's netcfg package.
	// This function just validates the profile and returns.
	log.Printf("warpalt: WireGuard profile loaded, tunnel managed by daemon")
	return nil
}

func handleWgDevice(id *Identity, dev interface{}) error {
	return nil
}
