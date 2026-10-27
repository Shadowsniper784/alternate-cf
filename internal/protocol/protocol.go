// Package protocol is the contract between the unprivileged GUI and the
// privileged warpaltd service. It is intentionally small: only data crosses
// the socket, never paths, commands or an interface name chosen by the client.
package protocol

import (
	"time"

	"warpalt/internal/routes"
	"warpalt/internal/warp"
)

// Version is bumped when the RPC surface or semantics change.
const Version = 1

// ServiceName is the RPC receiver name used over the Unix socket / named pipe.
const ServiceName = "Warpalt"

// Status is a snapshot of the daemon's tunnel and enrollment state. It never
// contains private keys or access tokens.
type Status struct {
	Version    int       `json:"version"`
	State      string    `json:"state"`
	Iface      string    `json:"iface,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Error      string    `json:"error,omitempty"`
	Enrolled   bool      `json:"enrolled"`
	Team       string    `json:"team,omitempty"`
	DeviceName string    `json:"deviceName,omitempty"`
	DeviceID   string    `json:"deviceId,omitempty"`
	IPv4       string    `json:"ipv4,omitempty"`
	IPv6       string    `json:"ipv6,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Mode       string    `json:"mode,omitempty"`
}

// ConnectRequest carries an already-enrolled identity and an already-computed
// routing plan. The daemon validates both; it never fetches policy or resolves
// hostnames itself.
type ConnectRequest struct {
	Identity warp.Identity `json:"identity"`
	Plan     routes.Plan   `json:"plan"`
	// Endpoint is host:port of the MASQUE endpoint.
	Endpoint string `json:"endpoint"`
	// Mode is "include" or "exclude", for status display only.
	Mode string `json:"mode,omitempty"`
	MTU  int    `json:"mtu,omitempty"`
}

// UpdatePlanRequest replaces the route plan of a live tunnel.
type UpdatePlanRequest struct {
	Plan routes.Plan `json:"plan"`
	Mode string      `json:"mode,omitempty"`
}

// IdentityInfo is the redacted identity the GUI may display.
type IdentityInfo struct {
	Enrolled   bool   `json:"enrolled"`
	Team       string `json:"team,omitempty"`
	DeviceName string `json:"deviceName,omitempty"`
	DeviceID   string `json:"deviceId,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// Ping is the version handshake.
type Ping struct {
	Version int `json:"version"`
}
