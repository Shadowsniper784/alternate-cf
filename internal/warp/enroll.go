package warp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/models"
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
// the MASQUE key, then persists the resulting identity.
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

// Reenroll refreshes the MASQUE key and endpoint configuration for an
// existing registration (used when the endpoint key rotated).
func Reenroll(id *Identity) (*Identity, error) {
	privKey, pubKey, err := GenerateEcKeyPair()
	if err != nil {
		return nil, err
	}
	// Re-enroll a fresh key against the stored registration.
	reg := models.AccountData{ID: id.DeviceID, Token: id.AccessToken}
	updated, apiErr, err := api.EnrollKey(reg, pubKey, id.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("re-enrolling device key: %w", err)
	}
	if apiErr != nil {
		return nil, fmt.Errorf("re-enrolling device key: %s", apiErr.ErrorsAsString("; "))
	}
	if len(updated.Config.Peers) == 0 {
		return nil, errors.New("re-enrollment returned no MASQUE peer")
	}
	peer := updated.Config.Peers[0]
	id.PrivateKey = encodeBase64(privKey)
	id.EndpointV4 = endpointHost(peer.Endpoint.V4)
	id.EndpointV6 = endpointHost(peer.Endpoint.V6)
	id.EndpointPubKey = peer.PublicKey
	if v := updated.Config.Interface.Addresses.V4; v != "" {
		id.IPv4 = v
	}
	if v := updated.Config.Interface.Addresses.V6; v != "" {
		id.IPv6 = v
	}
	if err := id.Save(); err != nil {
		return nil, err
	}
	return id, nil
}
