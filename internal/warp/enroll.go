package warp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Diniboy1123/usque/api"
)

// EnrollRequest describes one enrollment attempt from the UI.
type EnrollRequest struct {
	// Team is the subdomain of <team>.cloudflareaccess.com.
	Team string
	// TokenInput is whatever the user pasted from the enrollment success
	// page: a bare token or a com.cloudflare.warp:// / https URL.
	TokenInput string
	// DeviceName shown in the Zero Trust dashboard; defaults to hostname.
	DeviceName string
	// AcceptTOS must be true: registration is only allowed after the user
	// explicitly accepts Cloudflare's Terms of Service.
	AcceptTOS bool
}

// Enroll registers a new device against the given organization and enrolls
// the MASQUE key, then persist the resulting identity.
func Enroll(req EnrollRequest) (*Identity, error) {
	if !req.AcceptTOS {
		return nil, errors.New("you must accept Cloudflare's Terms of Service to register a device")
	}
	team, err := NormalizeTeam(req.Team)
	if err != nil {
		return nil, err
	}
	token, err := ParseTeamToken(req.TokenInput)
	if err != nil {
		return nil, err
	}

	deviceName := strings.TrimSpace(req.DeviceName)
	if deviceName == "" {
		deviceName = defaultDeviceName()
	}

	// Registration mirrors the official client: the team JWT is presented as
	// CF-Access-Jwt-Assertion by usque's api.Register.
	acct, err := api.Register("PC", "en_US", token, true)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	privKey, pubKey, err := GenerateEcKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating device key: %w", err)
	}

	updated, apiErr, err := api.EnrollKey(acct, pubKey, deviceName)
	if err != nil {
		return nil, fmt.Errorf("enrolling device key: %w", err)
	}
	if apiErr != nil {
		return nil, fmt.Errorf("enrolling device key: %s", apiErr.ErrorsAsString("; "))
	}
	if len(updated.Config.Peers) == 0 {
		return nil, errors.New("registration returned no MASQUE peer")
	}

	peer := updated.Config.Peers[0]
	id := &Identity{
		DeviceName:     deviceName,
		Team:           team,
		PrivateKey:     encodeBase64(privKey),
		EndpointV4:     endpointHost(peer.Endpoint.V4),
		EndpointV6:     endpointHost(peer.Endpoint.V6),
		EndpointPubKey: peer.PublicKey,
		DeviceID:       updated.ID,
		AccessToken:    acct.Token,
		IPv4:           updated.Config.Interface.Addresses.V4,
		IPv6:           updated.Config.Interface.Addresses.V6,
		Created:        updated.Created,
	}
	if id.IPv4 == "" {
		return nil, errors.New("registration returned no tunnel address")
	}
	if err := id.Save(); err != nil {
		return nil, err
	}
	return id, nil
}

// EnrollWireGuard registers a new device using WireGuard protocol.
// This registers with the API and then generates a WireGuard profile.
func EnrollWireGuard(req EnrollRequest) (*Identity, error) {
	if !req.AcceptTOS {
		return nil, errors.New("you must accept Cloudflare's Terms of Service to register a device")
	}
	team, err := NormalizeTeam(req.Team)
	if err != nil {
		return nil, err
	}
	token, err := ParseTeamToken(req.TokenInput)
	if err != nil {
		return nil, err
	}

	deviceName := strings.TrimSpace(req.DeviceName)
	if deviceName == "" {
		deviceName = defaultDeviceName()
	}

	// Generate WireGuard key pair for registration
	var kp *WgKeyPair
	kp, err = GenerateWgKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating WireGuard device key: %w", err)
	}

	// Register with the API using WireGuard key type and tunnel type
	// The usque library handles this through api.Register with WireGuard parameters
	// EnrollKey expects the raw public key bytes, so we decode the base64 public key
	pubKeyBytes, err := decodeBase64(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding WireGuard public key: %w", err)
	}
	_ = pubKeyBytes // used below for EnrollKey

	acct, err := api.Register("PC", "en_US", token, true)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Enroll the WireGuard public key (raw bytes)
	updated, apiErr, err := api.EnrollKey(acct, pubKeyBytes, deviceName)
	if err != nil {
		return nil, fmt.Errorf("enrolling WireGuard device key: %w", err)
	}
	if apiErr != nil {
		return nil, fmt.Errorf("enrolling WireGuard device key: %s", apiErr.ErrorsAsString("; "))
	}
	if len(updated.Config.Peers) == 0 {
		return nil, errors.New("registration returned no WireGuard peer")
	}

	peer := updated.Config.Peers[0]
	// Generate the WireGuard profile
	privateKeyB64 := kp.PrivateKey
	publicKeyB64 := kp.PublicKey

	endpoint := endpointHost(peer.Endpoint.V4)
	if endpoint == "" {
		endpoint = endpointHost(peer.Endpoint.V6)
	}
	endpoint = fmt.Sprintf("%s:2408", endpoint) // WireGuard uses port 2408

	profileData := &WgProfileData{
		PrivateKey: privateKeyB64,
		Address1:   updated.Config.Interface.Addresses.V4,
		Address2:   updated.Config.Interface.Addresses.V6,
		PublicKey:  publicKeyB64,
		Endpoint:   endpoint,
		Keepalive:  25, // Default keepalive
	}

	profileConfig, err := GenerateWgProfile(profileData)
	if err != nil {
		return nil, fmt.Errorf("generating WireGuard profile: %w", err)
	}

	// Store the profile config
	id := &Identity{
		DeviceName:     deviceName,
		Team:           team,
		PrivateKey:     privateKeyB64,
		EndpointV4:     updated.Config.Interface.Addresses.V4,
		EndpointV6:     updated.Config.Interface.Addresses.V6,
		EndpointPubKey: peer.PublicKey,
		DeviceID:       updated.ID,
		AccessToken:    acct.Token,
		IPv4:           updated.Config.Interface.Addresses.V4,
		IPv6:           updated.Config.Interface.Addresses.V6,
		Created:        updated.Created,
		Protocol:       "wireguard",
		WgProfile:      profileConfig,
	}
	if id.IPv4 == "" {
		return nil, errors.New("registration returned no tunnel address")
	}
	if err := id.Save(); err != nil {
		return nil, err
	}
	return id, nil
}

// EnrollWithProtocol registers a device with the specified protocol.
// protocol can be "masque" or "wireguard".
func EnrollWithProtocol(req EnrollRequest, protocol string) (*Identity, error) {
	switch protocol {
	case "masque":
		return Enroll(req)
	case "wireguard":
		return EnrollWireGuard(req)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocol)
	}
}
