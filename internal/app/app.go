package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"warpalt/internal/control"
	"warpalt/internal/protocol"
	"warpalt/internal/routes"
	"warpalt/internal/settings"
	"warpalt/internal/warp"
)

const policyTTL = 5 * time.Minute

// Status is the GUI-facing tunnel state.
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

// EnrollRequest is the enrollment form.
type EnrollRequest struct {
	Team       string `json:"team"`
	Token      string `json:"token"`
	DeviceName string `json:"deviceName"`
	AcceptTos  bool   `json:"acceptTos"`
	Protocol   string `json:"protocol"` // "masque" or "wireguard"
}

// EnrollResult is returned even when enrollment fails, so the UI can show the
// error without losing the current status.
type EnrollResult struct {
	Error  string `json:"error,omitempty"`
	Status Status `json:"status"`
}

// Application is the unprivileged Wails backend. It owns no sockets, routes or
// adapters; every privileged action is an RPC to warpaltd.
type Application struct {
	ctx context.Context

	policyMu  sync.Mutex
	policy    *warp.RemotePolicy
	policyAt  time.Time
	policyGen int
	fetching  bool

	resMu    sync.Mutex
	resolved map[string]resolution
}

// New creates the application.
func New() *Application {
	return &Application{resolved: make(map[string]resolution)}
}

// Startup stores the Wails context.
func (a *Application) Startup(ctx context.Context) {
	a.ctx = ctx
	vlogf("startup: backend ready (daemon endpoint %s)", control.Endpoint())
}

// verbose mirrors WARPALT_VERBOSE from the control package so every layer of
// the GUI writes its decisions to stdout when diagnosing a stuck window.
var verbose = os.Getenv("WARPALT_VERBOSE") != ""

func vlogf(format string, args ...any) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stdout, "[warpalt] "+format+"\n", args...)
}

// Log is called by the frontend so browser-side diagnostics reach stdout:
// the WebView does not forward console.log there by itself. It follows the
// same WARPALT_VERBOSE switch as the rest of the GUI.
func (a *Application) Log(msg string) {
	if !verbose {
		return
	}
	fmt.Fprintln(os.Stdout, "[ui] "+msg)
}

// Shutdown leaves the tunnel running: a VPN that drops when the window closes
// is not a VPN. The daemon is stopped by the service manager.
func (a *Application) Shutdown(context.Context) {}

// GetStatus returns the current daemon state, falling back to the local
// identity when the service is not running.
func (a *Application) GetStatus() Status {
	st, err := control.Status()
	if err != nil {
		vlogf("GetStatus: control.Status: %v", err)
		out := a.localStatus()
		if errors.Is(err, control.ErrUnavailable) {
			if out.Enrolled {
				msg := "warpaltd is not running. Install and start the warpalt service to enable the tunnel."
				if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
					msg = "Cannot access the warpalt control socket. Add your user to the warpalt group and log in again."
				}
				out.LastError = msg
			}
		} else {
			out.LastError = err.Error()
		}
		return out
	}
	out := fromProtocol(st)
	if !out.Enrolled {
		if id, err := warp.LoadIdentity(); err == nil && id.Validate() == nil {
			fillFromIdentity(&out, id)
		}
	}
	if out.LastError == "" && st.Error != "" {
		out.LastError = st.Error
	}
	return out
}

func (a *Application) localStatus() Status {
	out := Status{State: "disconnected"}
	if id, err := warp.LoadIdentity(); err == nil && id.Validate() == nil {
		fillFromIdentity(&out, id)
	}
	return out
}

func fromProtocol(st protocol.Status) Status {
	state := st.State
	if state == "" {
		state = "disconnected"
	}
	return Status{
		Enrolled:   st.Enrolled,
		Team:       st.Team,
		DeviceName: st.DeviceName,
		DeviceID:   st.DeviceID,
		IPv4:       st.IPv4,
		IPv6:       st.IPv6,
		Endpoint:   st.Endpoint,
		State:      state,
		Iface:      st.Iface,
		LastError:  st.Error,
	}
}

func fillFromIdentity(out *Status, id *warp.Identity) {
	out.Enrolled = true
	out.Team = id.Team
	out.DeviceName = id.DeviceName
	out.DeviceID = id.DeviceID
	out.IPv4 = id.IPv4
	out.IPv6 = id.IPv6
	if out.Endpoint == "" && (id.EndpointV4 != "" || id.EndpointV6 != "") {
		host := id.EndpointV4
		if host == "" {
			host = id.EndpointV6
		}
		out.Endpoint = net.JoinHostPort(host, "443")
	}
}

// GetSplit returns the split-tunnel screen.
func (a *Application) GetSplit() SplitView {
	return a.buildSplitView()
}

// Toggle connects or disconnects, whichever is appropriate.
func (a *Application) Toggle() Status {
	current := a.GetStatus()
	vlogf("Toggle: state=%q enrolled=%v", current.State, current.Enrolled)
	if current.State == "connected" || current.State == "reconnecting" {
		st, err := control.Disconnect()
		if err != nil {
			current.LastError = err.Error()
			return current
		}
		return fromProtocol(st)
	}
	if current.State == "connecting" {
		vlogf("Toggle: already connecting, ignoring disconnect request")
		return current
	}

	id, err := warp.LoadIdentity()
	if err != nil || id.Validate() != nil {
		current.LastError = "Not enrolled. Register this device first."
		return current
	}

	// Determine protocol from identity or ask user
	proto := id.Protocol
	if proto == "" {
		// Ask user which protocol to use
		proto = askUserProtocol()
		if proto == "" {
			current.LastError = "No protocol selected. Register with --protocol flag or set default."
			return current
		}
	}

	local := settings.Load()
	policy := a.remotePolicy(true)
	var plan routes.Plan
	// Use a different variable name to avoid shadowing the protocol package
	var endpoint string
	var mode string

	var warnings []string

	if proto == "wireguard" {
		// Use wireguard protocol
		if id.WgProfile == "" {
			current.LastError = "No WireGuard profile found. Register with wireguard protocol."
			return current
		}
		// Build plan from wireguard profile
		plan, mode, endpoint, warnings = a.buildPlanFromWgProfile(id.WgProfile)
		if endpoint == "" {
			current.LastError = strings.Join(warnings, "; ")
			if current.LastError == "" {
				current.LastError = "No usable WireGuard endpoint in the profile."
			}
			return current
		}
	} else {
		// MASQUE protocol (default behavior)
		plan, mode, endpoint, warnings = a.buildPlan(id, policy, local)
		if endpoint == "" {
			current.LastError = strings.Join(warnings, "; ")
			if current.LastError == "" {
				current.LastError = "No usable MASQUE endpoint in the enrollment."
			}
			return current
		}
	}

	vlogf("Toggle: connecting via %s (mode=%s, %d warnings)", endpoint, mode, len(warnings))
	st, err := control.Connect(protocol.ConnectRequest{
		Identity: *id,
		Plan:     plan,
		Endpoint: endpoint,
		Mode:     mode,
		MTU:      1280,
	})
	if err != nil {
		vlogf("Toggle: connect failed: %v", err)
		out := fromProtocol(st)
		out.LastError = err.Error()
		if !out.Enrolled {
			fillFromIdentity(&out, id)
		}
		return out
	}
	return fromProtocol(st)
}

// askUserProtocol prompts the user to select a protocol.
// This is a placeholder - in a real UI, this would show a dialog.
func askUserProtocol() string {
	// For now, default to masque since that's the existing behavior
	return "masque"
}

// buildPlanFromWgProfile builds a route plan from a WireGuard profile string.
func (a *Application) buildPlanFromWgProfile(profile string) (routes.Plan, string, string, []string) {
	var plan routes.Plan
	var mode string
	var endpoint string
	var warnings []string

	// Parse the WireGuard profile to extract endpoint and mode
	// For now, default to MASQUE-compatible settings
	mode = "exclude"
	endpoint = "162.159.197.2:443" // Default MASQUE endpoint

	// Extract from profile if available
	if strings.Contains(profile, "Endpoint=") {
		// Extract endpoint from profile
		idx := strings.Index(profile, "Endpoint=")
		if idx >= 0 {
			profile = profile[idx+9:]
			idx2 := strings.Index(profile, "\n")
			if idx2 >= 0 {
				profile = profile[:idx2]
			}
			endpoint = strings.TrimSpace(profile)
		}
	}

	// Build plan with wireguard-compatible routes
	local := settings.Load()
	// For wireguard, reuse the normal buildPlan logic with a dummy identity
	// and a fake remote policy - the WireGuard profile only provides the
	// endpoint, not the routing policy.
	id := warp.Identity{EndpointV4: endpoint}
	policy := &warp.RemotePolicy{
		Mode:    "exclude",
		Include: []warp.RouteEntry{},
		Exclude: []warp.RouteEntry{},
	}
	plan, mode, _, warnings = a.buildPlan(&id, policy, local)
	warnings = append(warnings, "WireGuard mode: using MASQUE-compatible routing")

	return plan, mode, endpoint, warnings
}

// Enroll registers a device and hands the identity to the daemon.
func (a *Application) Enroll(req EnrollRequest) EnrollResult {
	vlogf("Enroll: team=%q protocol=%q", req.Team, req.Protocol)
	id, err := warp.EnrollWithProtocol(warp.EnrollRequest{
		Team:       req.Team,
		TokenInput: req.Token,
		DeviceName: req.DeviceName,
		AcceptTOS:  req.AcceptTos,
	}, req.Protocol)
	if err != nil {
		vlogf("Enroll: failed: %v", err)
		return EnrollResult{Error: err.Error(), Status: a.GetStatus()}
	}
	a.invalidatePolicy()

	status := a.GetStatus()
	if _, err := control.PutIdentity(*id); err != nil {
		status = a.GetStatus()
		if !status.Enrolled {
			fillFromIdentity(&status, id)
		}
		status.LastError = "Enrolled and saved locally, but the tunnel service is not running: " + err.Error()
		return EnrollResult{Status: status}
	}
	return EnrollResult{Status: a.GetStatus()}
}

// OpenEnrollmentPage opens the team's device-enrollment page.
func (a *Application) OpenEnrollmentPage(team string) error {
	normalized, err := warp.NormalizeTeam(team)
	if err != nil {
		return err
	}
	return warp.OpenBrowser(warp.EnrollmentURL(normalized))
}

// SetLocalMode stores the fallback mode and reapplies it to a live tunnel.
func (a *Application) SetLocalMode(mode string) error {
	if mode != "include" && mode != "exclude" {
		return fmt.Errorf("unknown split-tunnel mode %q", mode)
	}
	local := settings.Load()
	local.LocalMode = mode
	if err := local.Save(); err != nil {
		return err
	}
	return a.reapply()
}

// AddLocalRoute validates, stores and applies a local route.
func (a *Application) AddLocalRoute(value string) (SplitView, error) {
	if err := validateEntry(value); err != nil {
		return SplitView{}, err
	}
	local := settings.Load()
	if err := local.AddLocalRoute(strings.TrimSpace(value)); err != nil {
		return SplitView{}, err
	}
	return a.afterLocalChange()
}

// RemoveLocalRoute removes a local route and reapplies the plan.
func (a *Application) RemoveLocalRoute(value string) (SplitView, error) {
	local := settings.Load()
	if err := local.RemoveLocalRoute(strings.TrimSpace(value)); err != nil {
		return SplitView{}, err
	}
	return a.afterLocalChange()
}

func (a *Application) afterLocalChange() (SplitView, error) {
	view := a.GetSplit()
	if err := a.reapply(); err != nil {
		view.Warnings = append(view.Warnings, "Saved, but the running tunnel could not apply the change: "+err.Error())
	}
	return view, nil
}

// RefreshPolicy forces a policy refetch and returns the refreshed view.
func (a *Application) RefreshPolicy() SplitView {
	a.invalidatePolicy()
	a.remotePolicy(true)
	return a.buildSplitView()
}

// Logout disconnects, forgets the daemon identity and removes the local one.
func (a *Application) Logout() error {
	_, _ = control.Logout()
	if id, err := warp.LoadIdentity(); err == nil {
		_ = id.Delete()
	}
	a.invalidatePolicy()
	return nil
}

// reapply pushes the current plan to a live tunnel, if there is one.
func (a *Application) reapply() error {
	status := a.GetStatus()
	if !isRunning(status.State) {
		return nil
	}
	id, err := warp.LoadIdentity()
	if err != nil {
		return err
	}
	plan, mode, _, _ := a.buildPlan(id, a.remotePolicy(true), settings.Load())
	_, err = control.UpdatePlan(plan, mode)
	return err
}

func (a *Application) invalidatePolicy() {
	a.policyMu.Lock()
	a.policy = nil
	a.policyAt = time.Time{}
	a.policyGen++
	a.policyMu.Unlock()
}

// remotePolicy returns the cached organization profile. With wait=false a
// stale or missing profile is refreshed in the background so the UI never
// blocks on the registration API.
func (a *Application) remotePolicy(wait bool) *warp.RemotePolicy {
	id, err := warp.LoadIdentity()
	if err != nil || id.Validate() != nil {
		vlogf("policy: not enrolled (%v)", err)
		return &warp.RemotePolicy{Error: "not enrolled"}
	}

	a.policyMu.Lock()
	if a.policy != nil {
		ttl := policyTTL
		if !a.policy.Available {
			ttl = 30 * time.Second
		}
		if time.Since(a.policyAt) < ttl {
			p := a.policy
			a.policyMu.Unlock()
			return p
		}
	}
	if !wait {
		p := a.policy
		if p == nil {
			p = &warp.RemotePolicy{Error: "organization settings are being fetched"}
			a.policy = p
			a.policyAt = time.Now().Add(-policyTTL)
		}
		start := !a.fetching
		if start {
			a.fetching = true
		}
		gen := a.policyGen
		a.policyMu.Unlock()
		if start {
			go func(id warp.Identity, gen int) {
				fetched := warp.FetchRemotePolicy(&id)
				vlogf("policy fetch: available=%v mode=%q error=%q", fetched.Available, fetched.Mode, fetched.Error)
				a.policyMu.Lock()
				defer a.policyMu.Unlock()
				if gen != a.policyGen {
					return
				}
				a.policy = fetched
				a.policyAt = time.Now()
				a.fetching = false
			}(*id, gen)
		}
		return p
	}
	gen := a.policyGen
	a.policyMu.Unlock()

	fetched := warp.FetchRemotePolicy(id)
	vlogf("policy fetch (waited): available=%v mode=%q error=%q", fetched.Available, fetched.Mode, fetched.Error)
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	if gen == a.policyGen {
		a.policy = fetched
		a.policyAt = time.Now()
	}
	a.fetching = false
	return fetched
}
