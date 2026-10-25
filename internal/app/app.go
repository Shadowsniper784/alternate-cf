// Package app exposes warpalt's state to the frontend through Wails bindings.
// Every method is a thin, thread-safe wrapper over the warp/routes/settings
// packages; heavy operations return channels so JavaScript sees promises.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"warpalt/internal/routes"
	"warpalt/internal/settings"
	"warpalt/internal/warp"
)

// Event names emitted to the frontend.
const (
	EventState  = "warp:state"
	EventPolicy = "warp:policy"
)

// Status is the snapshot the UI renders in its header.
type Status struct {
	Enrolled   bool   `json:"enrolled"`
	Team       string `json:"team"`
	DeviceName string `json:"deviceName"`
	DeviceID   string `json:"deviceId"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	Endpoint   string `json:"endpoint"`
	State      string `json:"state"`
	Iface      string `json:"iface"`
	LastError  string `json:"lastError"`
}

// Entry is one split-tunnel entry for the UI.
type Entry struct {
	Value       string `json:"value"`
	Kind        string `json:"kind"` // "address" | "host"
	Description string `json:"description,omitempty"`
}

// Conflict marks a local entry that overlaps an organization entry.
type Conflict struct {
	Org   string `json:"org"`
	Local string `json:"local"`
}

// SplitView is everything the split-tunnel tab needs.
type SplitView struct {
	Mode            string     `json:"mode"`       // effective mode
	ModeSource      string     `json:"modeSource"` // "organization" | "local"
	RemoteAvailable bool       `json:"remoteAvailable"`
	RemoteError     string     `json:"remoteError,omitempty"`
	RemoteNote      string     `json:"remoteNote,omitempty"`
	OrgEntries      []Entry    `json:"orgEntries"`
	LocalEntries    []Entry    `json:"localEntries"`
	Conflicts       []Conflict `json:"conflicts"`
	LocalMode       string     `json:"localMode"` // user's fallback preference
	Connected       bool       `json:"connected"`
	Warnings        []string   `json:"warnings,omitempty"`
}

// EnrollRequest is the enrollment form payload.
type EnrollRequest struct {
	Team       string `json:"team"`
	Token      string `json:"token"`
	DeviceName string `json:"deviceName"`
	AcceptTOS  bool   `json:"acceptTos"`
}

// EnrollResult pairs a status snapshot with a failure message so the UI can
// show either outcome from one awaited promise.
type EnrollResult struct {
	Error  string `json:"error,omitempty"`
	Status Status `json:"status"`
}

// App is the bound struct: window.go.app.App.*
type App struct {
	ctx      context.Context
	mu       sync.Mutex
	id       *warp.Identity
	policy   *warp.RemotePolicy
	settings *settings.Settings
	tunnel   *warp.Tunnel
	warnings []string
}

// New creates the application object (before the Wails runtime starts).
func New() *App {
	return &App{settings: settings.Load()}
}

// Startup runs when the Wails runtime is ready.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx

	id, err := warp.LoadIdentity()
	if err != nil {
		log.Printf("loading identity: %v", err)
	}
	a.mu.Lock()
	a.id = id
	if a.settings == nil {
		a.settings = settings.Load()
	}
	a.tunnel = warp.NewTunnel(a.onTunnelState)
	a.mu.Unlock()

	if id != nil {
		// Fetch the organization's policy in the background so the split
		// tunnel tab shows real remote settings right away.
		go func() {
			p := warp.FetchRemotePolicy(id)
			a.mu.Lock()
			a.policy = p
			a.mu.Unlock()
			a.emit(EventPolicy, a.GetSplit())
		}()
	}
}

// Shutdown stops the tunnel and restores routes before exit.
func (a *App) Shutdown(ctx context.Context) {
	a.mu.Lock()
	tun := a.tunnel
	a.mu.Unlock()
	if tun != nil {
		_ = tun.Stop()
	}
}

func (a *App) onTunnelState(state warp.TunnelState, lastErr string) {
	a.emit(EventState, map[string]string{"state": string(state), "error": lastErr})
}

func (a *App) emit(name string, payload any) {
	a.mu.Lock()
	ctx := a.ctx
	a.mu.Unlock()
	if ctx == nil {
		return
	}
	runtime.EventsEmit(ctx, name, payload)
}

// GetStatus returns the header snapshot.
func (a *App) GetStatus() Status {
	a.mu.Lock()
	id, tun := a.id, a.tunnel
	a.mu.Unlock()

	st := Status{Enrolled: id != nil}
	if id != nil {
		st.Team = id.Team
		st.DeviceName = id.DeviceName
		st.DeviceID = id.DeviceID
		st.IPv4 = id.IPv4
		st.IPv6 = id.IPv6
		st.Endpoint = id.EndpointV4
	}
	if tun != nil {
		state, iface, lastErr := tun.Status()
		st.State = string(state)
		st.Iface = iface
		st.LastError = lastErr
	} else {
		st.State = string(warp.StateDisconnected)
	}
	return st
}

// GetSplit returns the split-tunnel view from cached data (no network).
func (a *App) GetSplit() SplitView {
	a.mu.Lock()
	policy := a.policy
	var localValues []string
	localMode := "exclude"
	if a.settings != nil {
		localMode = a.settings.LocalMode
		localValues = append([]string{}, a.settings.LocalRoutes...)
	}
	connected := false
	if a.tunnel != nil {
		state, _, _ := a.tunnel.Status()
		connected = state == warp.StateConnected || state == warp.StateConnecting || state == warp.StateReconnecting
	}
	warnings := append([]string{}, a.warnings...)
	a.mu.Unlock()

	view := SplitView{
		OrgEntries:   []Entry{},
		LocalEntries: []Entry{},
		Conflicts:    []Conflict{},
		Connected:    connected,
		LocalMode:    localMode,
		Warnings:     warnings,
	}
	for _, v := range localValues {
		view.LocalEntries = append(view.LocalEntries, Entry{Value: v, Kind: kindOf(v)})
	}

	view.RemoteAvailable = policy != nil && policy.Available
	if policy != nil && policy.Available {
		view.RemoteError = policy.Error
		view.RemoteNote = policy.Describe()
		view.Mode = policy.EffectiveMode(localMode)
		view.ModeSource = "organization"
		for _, e := range policy.OrgEntries(view.Mode) {
			view.OrgEntries = append(view.OrgEntries, Entry{
				Value:       e.Value(),
				Kind:        kindOf(e.Value()),
				Description: e.Description,
			})
		}
	} else {
		if policy != nil {
			view.RemoteError = policy.Error
			view.RemoteNote = policy.Describe()
		}
		view.Mode = localMode
		view.ModeSource = "local"
	}

	// Conflicts: local entries overlapping organization entries.
	orgPrefixes, _ := resolveValues(orgValues(policy, view.Mode), false)
	localPrefixes, _ := resolveValues(localValues, false)
	for _, c := range routes.Conflicts(orgPrefixes, localPrefixes) {
		view.Conflicts = append(view.Conflicts, Conflict{Org: c[0].String(), Local: c[1].String()})
	}
	return view
}

func orgValues(policy *warp.RemotePolicy, mode string) []string {
	if policy == nil || !policy.Available {
		return nil
	}
	var out []string
	for _, e := range policy.OrgEntries(mode) {
		out = append(out, e.Value())
	}
	return out
}

// RefreshPolicy fetches the organization's device profile asynchronously.
func (a *App) RefreshPolicy() chan SplitView {
	out := make(chan SplitView, 1)
	a.mu.Lock()
	id := a.id
	a.mu.Unlock()
	go func() {
		if id != nil {
			p := warp.FetchRemotePolicy(id)
			a.mu.Lock()
			a.policy = p
			a.mu.Unlock()
		}
		out <- a.GetSplit()
		close(out)
	}()
	return out
}

// Enroll registers a device for the given team subdomain.
func (a *App) Enroll(req EnrollRequest) chan EnrollResult {
	out := make(chan EnrollResult, 1)
	go func() {
		id, err := warp.Enroll(warp.EnrollRequest{
			Team:       req.Team,
			TokenInput: req.Token,
			DeviceName: req.DeviceName,
			AcceptTOS:  req.AcceptTOS,
		})
		if err != nil {
			out <- EnrollResult{Error: err.Error(), Status: a.GetStatus()}
			close(out)
			return
		}
		a.mu.Lock()
		a.id = id
		a.policy = nil
		a.mu.Unlock()
		go func() {
			p := warp.FetchRemotePolicy(id)
			a.mu.Lock()
			a.policy = p
			a.mu.Unlock()
			a.emit(EventPolicy, a.GetSplit())
		}()
		out <- EnrollResult{Status: a.GetStatus()}
		close(out)
	}()
	return out
}

// OpenEnrollmentPage opens the organization's /warp sign-in page.
func (a *App) OpenEnrollmentPage(team string) error {
	t, err := warp.NormalizeTeam(team)
	if err != nil {
		return err
	}
	return warp.OpenBrowser(warp.EnrollmentURL(t))
}

// Toggle is the enable/disable button: it connects (applying the split
// tunnel) or disconnects (restoring routes). Failures land in Status.LastError.
func (a *App) Toggle() chan Status {
	out := make(chan Status, 1)
	go func() {
		if a.isRunning() {
			a.mu.Lock()
			tun := a.tunnel
			a.mu.Unlock()
			if tun != nil {
				_ = tun.Stop()
			}
		} else if err := a.connect(); err != nil {
			a.emit("warp:error", err.Error())
		}
		out <- a.GetStatus()
		close(out)
	}()
	return out
}

func (a *App) isRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunnel == nil {
		return false
	}
	state, _, _ := a.tunnel.Status()
	switch state {
	case warp.StateConnecting, warp.StateConnected, warp.StateReconnecting:
		return true
	}
	return false
}

// connect computes the effective split tunnel and starts it.
func (a *App) connect() error {
	a.mu.Lock()
	id, set, tun := a.id, a.settings, a.tunnel
	a.mu.Unlock()

	if id == nil {
		return errors.New("device is not enrolled")
	}
	if set == nil {
		set = &settings.Settings{LocalMode: "exclude"}
	}
	if tun == nil {
		return errors.New("tunnel is not initialised")
	}

	// Always refresh the organization's settings at connect time: remote
	// policy is authoritative and may have changed since we last looked.
	policy := warp.FetchRemotePolicy(id)
	a.mu.Lock()
	a.policy = policy
	a.mu.Unlock()

	mode := policy.EffectiveMode(set.LocalMode)

	orgList := orgValues(policy, mode)
	if !policy.Available && mode == "exclude" {
		// Without organization settings, fall back to Cloudflare's
		// recommended default exclusions so the local network and the
		// machine's own services keep working.
		orgList = defaultExclusions()
	}

	localValues := append([]string{}, set.LocalRoutes...)

	orgPrefixes, orgWarn := resolveValues(orgList, true)
	localPrefixes, localWarn := resolveValues(localValues, true)
	warnings := append([]string{}, orgWarn...)
	warnings = append(warnings, localWarn...)

	endpoint := netip.Addr{}
	if id.EndpointV4 != "" {
		if v, err := netip.ParseAddr(id.EndpointV4); err == nil {
			endpoint = v
		}
	} else if id.EndpointV6 != "" {
		if v, err := netip.ParseAddr(id.EndpointV6); err == nil {
			endpoint = v
		}
	}

	plan := routes.Build(mode, orgPrefixes, localPrefixes, endpoint)

	a.mu.Lock()
	a.warnings = warnings
	a.mu.Unlock()

	if err := tun.Start(id, plan); err != nil {
		return err
	}
	a.emit(EventPolicy, a.GetSplit())
	return nil
}

// SetLocalMode sets the fallback mode used when no organization policy is
// available. Only applies on the next connect.
func (a *App) SetLocalMode(mode string) error {
	if mode != "include" && mode != "exclude" {
		return errors.New("mode must be include or exclude")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settings == nil {
		a.settings = settings.Load()
	}
	a.settings.LocalMode = mode
	return a.settings.Save()
}

// AddLocalRoute adds a user entry ("route through the tunnel"): an IP/CIDR
// or a hostname.
func (a *App) AddLocalRoute(value string) (SplitView, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return SplitView{}, errors.New("enter an IP, CIDR or hostname")
	}
	if err := validateEntry(v); err != nil {
		return SplitView{}, err
	}

	a.mu.Lock()
	if a.settings == nil {
		a.settings = settings.Load()
	}
	err := a.settings.AddLocalRoute(v)
	running := a.tunnel != nil && isRunningLocked(a.tunnel)
	a.mu.Unlock()
	if err != nil {
		return SplitView{}, err
	}
	if running {
		a.reconnect()
	}
	return a.GetSplit(), nil
}

// RemoveLocalRoute removes a user entry.
func (a *App) RemoveLocalRoute(value string) (SplitView, error) {
	a.mu.Lock()
	if a.settings == nil {
		a.settings = settings.Load()
	}
	err := a.settings.RemoveLocalRoute(value)
	running := a.tunnel != nil && isRunningLocked(a.tunnel)
	a.mu.Unlock()
	if err != nil {
		return SplitView{}, err
	}
	if running {
		a.reconnect()
	}
	return a.GetSplit(), nil
}

// reconnect restarts the tunnel so routing changes take effect.
func (a *App) reconnect() {
	go func() {
		a.mu.Lock()
		tun := a.tunnel
		a.mu.Unlock()
		if tun == nil {
			return
		}
		_ = tun.Stop()
		if err := a.connect(); err != nil {
			a.emit("warp:error", err.Error())
		}
	}()
}

// Logout stops the tunnel and forgets the registration.
func (a *App) Logout() error {
	a.mu.Lock()
	tun := a.tunnel
	a.mu.Unlock()
	if tun != nil {
		_ = tun.Stop()
	}
	if err := warp.Delete(); err != nil {
		return err
	}
	a.mu.Lock()
	a.id = nil
	a.policy = nil
	a.warnings = nil
	a.mu.Unlock()
	return nil
}

// ---- helpers ----

func isRunningLocked(t *warp.Tunnel) bool {
	state, _, _ := t.Status()
	switch state {
	case warp.StateConnecting, warp.StateConnected, warp.StateReconnecting:
		return true
	}
	return false
}

func kindOf(v string) string {
	if _, err := netip.ParsePrefix(v); err == nil {
		return "address"
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return "address"
	}
	return "host"
}

func validateEntry(v string) error {
	if _, err := netip.ParsePrefix(v); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return nil
	}
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_'
		if !ok {
			return fmt.Errorf("%q is not an IP, CIDR or hostname", v)
		}
	}
	if len(v) == 0 || strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") || strings.HasSuffix(v, "-") {
		return fmt.Errorf("%q is not a valid hostname", v)
	}
	return nil
}

// resolveValues turns entries into prefixes; hostnames are resolved when
// resolve is true (at connect time). Unresolvable entries become warnings.
func resolveValues(values []string, resolve bool) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var warnings []string
	seen := map[netip.Prefix]struct{}{}

	add := func(p netip.Prefix) {
		p = p.Masked()
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, v := range values {
		if p, err := netip.ParsePrefix(v); err == nil {
			add(p)
			continue
		}
		if a, err := netip.ParseAddr(v); err == nil {
			add(netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		if !resolve {
			continue
		}
		ips, err := lookupHost(v)
		if err != nil || len(ips) == 0 {
			warnings = append(warnings, fmt.Sprintf("could not resolve %q; entry skipped", v))
			continue
		}
		for _, ip := range ips {
			add(netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out, warnings
}

func lookupHost(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// defaultExclusions mirrors Cloudflare's recommended default split-tunnel
// exclusions, used only when no organization policy could be fetched.
func defaultExclusions() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	}
}
