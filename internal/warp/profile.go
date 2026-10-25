package warp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The constants below mirror usque's module-internal API constants (the same
// public registration endpoint the official Android client uses).
const (
	apiURL     = "https://api.cloudflareclient.com"
	apiVersion = "v0a4471"
)

var apiHeaders = map[string]string{
	"User-Agent":       "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":     "application/json; charset=UTF-8",
	"Connection":       "Keep-Alive",
}

// RouteEntry is one split-tunnel entry as Cloudflare returns it: either a
// CIDR address or a hostname.
type RouteEntry struct {
	Address     string `json:"address,omitempty"`
	Host        string `json:"host,omitempty"`
	Description string `json:"description,omitempty"`
}

// IsAddress reports whether the entry is an IP/CIDR rather than a hostname.
func (e RouteEntry) IsAddress() bool { return e.Address != "" }

// Value returns the entry's address or host.
func (e RouteEntry) Value() string {
	if e.Address != "" {
		return e.Address
	}
	return e.Host
}

// RemotePolicy is the organization's device profile as returned to the
// enrolled device. It is authoritative: warpalt applies it as the base
// routing configuration and only layers explicit local additions on top.
type RemotePolicy struct {
	// Available is false when the policy could not be retrieved; the UI then
	// falls back to local configuration and says so.
	Available bool `json:"available"`
	// Mode is "include" or "exclude"; empty when Cloudflare did not say.
	Mode string `json:"mode,omitempty"`
	// ServiceMode is the client mode ("warp", "1dot1", "proxy", ...).
	ServiceMode string     `json:"serviceMode,omitempty"`
	Include     []RouteEntry `json:"include,omitempty"`
	Exclude     []RouteEntry `json:"exclude,omitempty"`
	// Error explains an unavailable policy in user-facing terms.
	Error     string    `json:"error,omitempty"`
	FetchedAt time.Time `json:"fetchedAt,omitempty"`
}

// policyPayload is the tolerant shape of the registration document: the
// policy block may sit at the top level or under "result".
type policyPayload struct {
	Policy *policyBlock `json:"policy"`
	Result *struct {
		Policy *policyBlock `json:"policy"`
	} `json:"result"`
}

type policyBlock struct {
	ServiceMode   string       `json:"service_mode"`
	ServiceModeV2 struct {
		Mode string `json:"mode"`
	} `json:"service_mode_v2"`
	Include []RouteEntry `json:"include"`
	Exclude []RouteEntry `json:"exclude"`
}

// FetchRemotePolicy downloads the current device registration document and
// extracts the split-tunnel policy. This is the reverse-engineered
// registration read (GET /<version>/reg/<device id>) that community clients
// use; it is not a documented Cloudflare contract, so failures degrade to
// Available=false rather than blocking the UI.
func FetchRemotePolicy(id *Identity) *RemotePolicy {
	out := &RemotePolicy{FetchedAt: time.Now()}

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/%s/reg/%s", apiURL, apiVersion, id.DeviceID), nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for k, v := range apiHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+id.AccessToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		out.Error = "policy request failed: " + err.Error()
		return out
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		out.Error = "reading policy response: " + err.Error()
		return out
	}
	if resp.StatusCode != http.StatusOK {
		out.Error = fmt.Sprintf("policy request returned HTTP %d", resp.StatusCode)
		return out
	}

	block, err := parsePolicyBlock(body)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if block == nil {
		out.Error = "registration response contained no policy block"
		return out
	}

	out.Available = true
	out.ServiceMode = block.ServiceModeV2.Mode
	if out.ServiceMode == "" {
		out.ServiceMode = block.ServiceMode
	}
	out.Include = block.Include
	out.Exclude = block.Exclude

	// A profile carries either an include or an exclude list; derive the mode
	// from which one is populated when Cloudflare did not state it.
	switch {
	case len(block.Exclude) > 0 && len(block.Include) == 0:
		out.Mode = "exclude"
	case len(block.Include) > 0 && len(block.Exclude) == 0:
		out.Mode = "include"
	case len(block.Exclude) > 0 && len(block.Include) > 0:
		// Both present: treat non-empty exclude as exclude mode (the default
		// profile shape) - the UI shows both lists verbatim regardless.
		out.Mode = "exclude"
	}
	return out
}

func parsePolicyBlock(body []byte) (*policyBlock, error) {
	var payload policyPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("unexpected policy JSON: %w", err)
	}
	if payload.Policy != nil {
		return payload.Policy, nil
	}
	if payload.Result != nil && payload.Result.Policy != nil {
		return payload.Result.Policy, nil
	}
	// Some responses nest policy inside a bare "result" object without a
	// policy key - probe for a direct include/exclude pair at top level.
	var probe struct {
		Include []RouteEntry `json:"include"`
		Exclude []RouteEntry `json:"exclude"`
	}
	if err := json.Unmarshal(body, &probe); err == nil &&
		(len(probe.Include) > 0 || len(probe.Exclude) > 0) {
		return &policyBlock{Include: probe.Include, Exclude: probe.Exclude}, nil
	}
	return nil, nil
}

// EffectiveMode resolves which split-tunnel mode applies: the organization's
// mode when the remote policy is available (deriving it from the populated
// list when Cloudflare did not state it explicitly), otherwise the local
// preference.
func (p *RemotePolicy) EffectiveMode(local string) string {
	if p != nil && p.Available {
		switch {
		case p.Mode != "":
			return p.Mode
		case len(p.Exclude) > 0 && len(p.Include) == 0:
			return "exclude"
		case len(p.Include) > 0 && len(p.Exclude) == 0:
			return "include"
		}
	}
	if local == "include" || local == "exclude" {
		return local
	}
	return "exclude"
}

// OrgEntries returns the organization's split-tunnel entries as a single
// list (the active one for the resolved mode).
func (p *RemotePolicy) OrgEntries(mode string) []RouteEntry {
	if p == nil || !p.Available {
		return nil
	}
	if mode == "include" {
		return p.Include
	}
	return p.Exclude
}

// Describe renders a short, user-facing summary of the remote policy state.
func (p *RemotePolicy) Describe() string {
	if p == nil || !p.Available {
		msg := "organization settings not retrieved"
		if p != nil && p.Error != "" {
			msg += ": " + p.Error
		}
		return msg
	}
	n := len(p.Include) + len(p.Exclude)
	if n == 0 {
		return "organization settings retrieved (no split-tunnel entries)"
	}
	return fmt.Sprintf("organization settings retrieved (%d %s entries)", n, strings.ToLower(p.Mode))
}
