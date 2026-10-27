// Package daemon is the privileged half of warpalt. The GUI sends it an
// enrolled identity and a routing plan; the daemon creates the TUN device,
// installs the routes, runs the MASQUE engine and reports state back. It never
// fetches policy, resolves hostnames or accepts a device path from a client.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"warpalt/internal/control"
	"warpalt/internal/engine"
	"warpalt/internal/netcfg"
	"warpalt/internal/protocol"
	"warpalt/internal/routes"
	"warpalt/internal/warp"
)

// Daemon is the service state. It is safe for concurrent RPC calls.
type Daemon struct {
	mu       sync.Mutex
	listener net.Listener
	closed   bool

	state      string
	detail     string
	iface      string
	since      time.Time
	generation int

	identity *warp.Identity
	plan     routes.Plan
	mode     string
	endpoint string

	dev         *netcfg.Device
	routeHandle routes.RouteHandle
	cancel      context.CancelFunc
}

// vlogf writes a diagnostic line to stdout when WARPALT_VERBOSE is set so a
// foreground daemon run (sudo ./warpaltd -v) shows exactly what it is doing.
func vlogf(format string, args ...any) {
	if os.Getenv("WARPALT_VERBOSE") == "" {
		return
	}
	fmt.Fprintf(os.Stdout, "[warpaltd] "+format+"\n", args...)
}

// New creates a daemon and loads the identity persisted by a previous run.
func New() *Daemon {
	// Remove routes left on a persistent Wintun adapter by a crashed run.
	netcfg.Cleanup()

	d := &Daemon{
		state: "disconnected",
		since: time.Now(),
	}
	d.loadIdentity()
	vlogf("started (enrolled=%v, endpoint %s)", d.identity != nil, control.Endpoint())
	return d
}

// Serve listens for control clients until Close is called.
func (d *Daemon) Serve() error {
	d.mu.Lock()
	if d.listener != nil {
		d.mu.Unlock()
		return errors.New("daemon is already serving")
	}
	d.mu.Unlock()

	l, err := listen()
	if err != nil {
		return err
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = l.Close()
		return nil
	}
	d.listener = l
	d.mu.Unlock()

	srv := rpc.NewServer()
	if err := srv.RegisterName(protocol.ServiceName, &rpcAPI{d: d}); err != nil {
		_ = l.Close()
		return fmt.Errorf("registering RPC service: %w", err)
	}
	vlogf("serving control RPC on %s", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			if d.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accepting control connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := authorize(c); err != nil {
				log.Printf("warpaltd: rejected control client: %v", err)
				vlogf("rejected control client: %v", err)
				return
			}
			vlogf("control client connected: %s", c.RemoteAddr())
			srv.ServeCodec(jsonrpc.NewServerCodec(c))
		}(conn)
	}
}

// Close stops the listener and tears down any live tunnel. It is idempotent.
func (d *Daemon) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	l := d.listener
	d.listener = nil
	d.disconnectLocked()
	d.mu.Unlock()

	if l != nil {
		_ = l.Close()
	}
	return nil
}

func (d *Daemon) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// Status returns a redacted snapshot.
func (d *Daemon) Status() protocol.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.statusLocked()
}

func (d *Daemon) statusLocked() protocol.Status {
	s := protocol.Status{
		Version:  protocol.Version,
		State:    d.state,
		Iface:    d.iface,
		Since:    d.since,
		Error:    d.detail,
		Mode:     d.mode,
		Endpoint: d.endpoint,
	}
	if id := d.identity; id != nil {
		s.Enrolled = true
		s.Team = id.Team
		s.DeviceName = id.DeviceName
		s.DeviceID = id.DeviceID
		s.IPv4 = id.IPv4
		s.IPv6 = id.IPv6
		if s.Endpoint == "" {
			s.Endpoint = endpointFor(id)
		}
	}
	return s
}

// Connect brings the tunnel up. It is idempotent in the sense that an existing
// tunnel is torn down first.
func (d *Daemon) Connect(req protocol.ConnectRequest) (protocol.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return d.statusLocked(), errors.New("daemon is shutting down")
	}
	id := req.Identity
	if err := id.Validate(); err != nil {
		d.setDetailLocked("error", err.Error())
		return d.statusLocked(), err
	}
	if req.Endpoint == "" {
		req.Endpoint = endpointFor(&id)
	}
	if req.Endpoint == "" {
		err := errors.New("no MASQUE endpoint available")
		d.setDetailLocked("error", err.Error())
		return d.statusLocked(), err
	}
	mtu := req.MTU
	if mtu <= 0 {
		mtu = netcfg.DefaultMTU
	}
	vlogf("Connect: endpoint=%s mode=%q mtu=%d", req.Endpoint, req.Mode, mtu)

	if d.dev != nil || d.cancel != nil {
		d.disconnectLocked()
	}
	d.generation++

	dev, err := netcfg.Create(id.IPv4, id.IPv6, mtu)
	if err != nil {
		d.setDetailLocked("error", err.Error())
		return d.statusLocked(), err
	}

	plan := req.Plan
	h, err := routes.RouteApply(&plan, dev.Name())
	if err != nil {
		_ = dev.Close()
		d.setDetailLocked("error", err.Error())
		return d.statusLocked(), fmt.Errorf("applying routes: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.identity = &id
	d.plan = plan
	d.mode = req.Mode
	d.endpoint = req.Endpoint
	d.dev = dev
	d.routeHandle = h
	d.cancel = cancel
	d.iface = dev.Name()
	d.state = "connecting"
	d.detail = ""
	d.since = time.Now()

	if err := d.saveIdentityLocked(); err != nil {
		log.Printf("warpaltd: persisting identity: %v", err)
	}

	gen := d.generation
	go d.runEngine(gen, ctx, id, dev.Device(), req.Endpoint, mtu)
	return d.statusLocked(), nil
}

func (d *Daemon) runEngine(gen int, ctx context.Context, id warp.Identity, dev tun.Device, endpoint string, mtu int) {
	err := engine.Run(ctx, engine.Config{
		Identity: &id,
		Device:   dev,
		Endpoint: endpoint,
		MTU:      mtu,
		OnState: func(state, detail string) {
			d.engineState(gen, state, detail)
		},
	})

	d.mu.Lock()
	defer d.mu.Unlock()
	if gen != d.generation {
		return
	}
	if err != nil {
		d.disconnectLocked()
		d.state = "error"
		d.detail = err.Error()
		d.since = time.Now()
	}
}

func (d *Daemon) engineState(gen int, state, detail string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if gen != d.generation || d.dev == nil {
		return
	}
	d.state = state
	if state == "connected" {
		d.detail = ""
		d.since = time.Now()
	} else if detail != "" {
		d.detail = detail
	}
}

// Disconnect tears the tunnel down; it succeeds even when already down.
func (d *Daemon) Disconnect() protocol.Status {
	vlogf("Disconnect called")
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disconnectLocked()
	return d.statusLocked()
}

func (d *Daemon) disconnectLocked() {
	vlogf("disconnectLocked called")
	d.generation++
	if d.cancel != nil {
		vlogf("cancelling context")
		d.cancel()
		d.cancel = nil
	}
	if d.routeHandle != nil {
		if err := d.routeHandle.Remove(); err != nil {
			log.Printf("warpaltd: removing routes: %v", err)
		}
		d.routeHandle = nil
	}
	if d.dev != nil {
		if err := d.dev.Close(); err != nil {
			log.Printf("warpaltd: closing tunnel device: %v", err)
		}
		d.dev = nil
	}
	d.state = "disconnected"
	d.detail = ""
	d.iface = ""
	d.endpoint = ""
	d.since = time.Now()
}

// UpdatePlan swaps the route plan of a live tunnel, rolling back to the old
// plan if the new one cannot be applied.
func (d *Daemon) UpdatePlan(req protocol.UpdatePlanRequest) (protocol.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dev == nil {
		d.plan = req.Plan
		if req.Mode != "" {
			d.mode = req.Mode
		}
		return d.statusLocked(), nil
	}

	oldPlan := d.plan
	if d.routeHandle != nil {
		if err := d.routeHandle.Remove(); err != nil {
			return d.statusLocked(), fmt.Errorf("removing previous routes: %w", err)
		}
		d.routeHandle = nil
	}
	newPlan := req.Plan
	h, err := routes.RouteApply(&newPlan, d.dev.Name())
	if err != nil {
		// Best effort rollback so a bad local entry cannot leave the tunnel
		// without any routes.
		if rollback, rerr := routes.RouteApply(&oldPlan, d.dev.Name()); rerr == nil {
			d.routeHandle = rollback
		}
		return d.statusLocked(), fmt.Errorf("applying routes: %w", err)
	}
	d.routeHandle = h
	d.plan = newPlan
	if req.Mode != "" {
		d.mode = req.Mode
	}
	return d.statusLocked(), nil
}

// PutIdentity validates and persists the enrolled identity. A live tunnel is
// stopped because its identity is now stale.
func (d *Daemon) PutIdentity(id warp.Identity) (protocol.Status, error) {
	if err := id.Validate(); err != nil {
		return d.Status(), err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev != nil || d.cancel != nil {
		d.disconnectLocked()
	}
	d.identity = &id
	if err := d.saveIdentityLocked(); err != nil {
		return d.statusLocked(), fmt.Errorf("saving identity: %w", err)
	}
	return d.statusLocked(), nil
}

// Logout forgets the daemon-side identity.
func (d *Daemon) Logout() protocol.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disconnectLocked()
	d.identity = nil
	if path, err := stateFile(); err == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("warpaltd: removing identity: %v", err)
		}
	}
	return d.statusLocked()
}

// Identity returns the redacted identity information.
func (d *Daemon) Identity() protocol.IdentityInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := protocol.IdentityInfo{}
	if id := d.identity; id != nil {
		out = protocol.IdentityInfo{
			Enrolled:   true,
			Team:       id.Team,
			DeviceName: id.DeviceName,
			DeviceID:   id.DeviceID,
			IPv4:       id.IPv4,
			IPv6:       id.IPv6,
			Endpoint:   endpointFor(id),
		}
	}
	return out
}

func (d *Daemon) setDetailLocked(state, detail string) {
	d.state = state
	d.detail = detail
	d.since = time.Now()
}

func (d *Daemon) loadIdentity() {
	path, err := stateFile()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warpaltd: reading identity: %v", err)
		}
		return
	}
	plain, err := unseal(raw)
	if err != nil {
		log.Printf("warpaltd: unsealing identity: %v", err)
		return
	}
	var id warp.Identity
	if err := json.Unmarshal(plain, &id); err != nil {
		log.Printf("warpaltd: decoding identity: %v", err)
		return
	}
	if err := id.Validate(); err != nil {
		log.Printf("warpaltd: ignoring invalid stored identity: %v", err)
		return
	}
	d.identity = &id
}

func (d *Daemon) saveIdentityLocked() error {
	if d.identity == nil {
		return nil
	}
	path, err := stateFile()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(d.identity)
	if err != nil {
		return err
	}
	sealed, err := seal(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, sealed, 0o600)
}

// endpointFor prefers IPv4, matching the official client's behaviour on
// dual-stack hosts.
func endpointFor(id *warp.Identity) string {
	host := id.EndpointV4
	if host == "" {
		host = id.EndpointV6
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, "443")
}

// rpcAPI adapts Daemon to net/rpc. Every method has the required signature.
type rpcAPI struct {
	d *Daemon
}

func (a *rpcAPI) Ping(_ struct{}, out *protocol.Ping) error {
	*out = protocol.Ping{Version: protocol.Version}
	return nil
}

func (a *rpcAPI) Status(_ struct{}, out *protocol.Status) error {
	*out = a.d.Status()
	return nil
}

func (a *rpcAPI) Connect(req protocol.ConnectRequest, out *protocol.Status) error {
	status, err := a.d.Connect(req)
	*out = status
	return err
}

func (a *rpcAPI) Disconnect(_ struct{}, out *protocol.Status) error {
	*out = a.d.Disconnect()
	return nil
}

func (a *rpcAPI) UpdatePlan(req protocol.UpdatePlanRequest, out *protocol.Status) error {
	status, err := a.d.UpdatePlan(req)
	*out = status
	return err
}

func (a *rpcAPI) PutIdentity(id warp.Identity, out *protocol.Status) error {
	status, err := a.d.PutIdentity(id)
	*out = status
	return err
}

func (a *rpcAPI) Logout(_ struct{}, out *protocol.Status) error {
	*out = a.d.Logout()
	return nil
}

func (a *rpcAPI) GetIdentity(_ struct{}, out *protocol.IdentityInfo) error {
	*out = a.d.Identity()
	return nil
}
