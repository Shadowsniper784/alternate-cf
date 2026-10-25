package warp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"github.com/songgao/water"

	"warpalt/internal/routes"
)

// TunnelState is the user-facing connection state.
type TunnelState string

const (
	StateDisconnected TunnelState = "disconnected"
	StateConnecting   TunnelState = "connecting"
	StateConnected    TunnelState = "connected"
	StateReconnecting TunnelState = "reconnecting"
	StateError        TunnelState = "error"
)

// Connect-IP encodes its context ID as a one-byte QUIC varint; reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place
// (same convention as usque's tunnel loop).
const datagramContextIDHeadroom = 1

// pumpShutdownGrace bounds how long Stop waits for forwarding goroutines to
// leave a blocking TUN read before the device is closed underneath them.
const pumpShutdownGrace = 2 * time.Second

// reconnectionDelay between MASQUE attempts.
const reconnectionDelay = 2 * time.Second

// masqueSNI is the SNI used for the consumer/Zero Trust MASQUE endpoint.
// usque uses this for all registrations (its alternate zt-masque SNI is marked
// unused upstream); it works for team registrations too.
const masqueSNI = "consumer-masque.cloudflareclient.com"

// connectURI is the CONNECT-IP request authority (mirrors usque).
const connectURI = "https://cloudflareaccess.com"

// Tunnel owns the TUN device, the route handle and the MASQUE session.
type Tunnel struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	dev     *water.Interface
	handle  *routes.Handle
	iface   string
	state   TunnelState
	lastErr string
	onState func(TunnelState, string)
}

// NewTunnel creates a stopped tunnel. onState is invoked (from background
// goroutines) whenever the connection state changes.
func NewTunnel(onState func(TunnelState, string)) *Tunnel {
	return &Tunnel{state: StateDisconnected, onState: onState}
}

// Status reports the current state, interface name and last error.
func (t *Tunnel) Status() (TunnelState, string, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state, t.iface, t.lastErr
}

// Start brings the tunnel up: TUN device, routes, then the MASQUE session.
// plan must already describe the effective split tunnel.
func (t *Tunnel) Start(id *Identity, plan routes.Plan) error {
	t.mu.Lock()
	if t.cancel != nil {
		t.mu.Unlock()
		return errors.New("tunnel is already running")
	}
	t.mu.Unlock()

	dev, err := createTUN(id)
	if err != nil {
		return fmt.Errorf("creating tunnel device (are you running as root/administrator?): %w", err)
	}

	handle, err := routes.Apply(plan, dev.Name())
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("applying split-tunnel routes: %w", err)
	}

	tlsConfig, endpoint, quicConfig, err := buildSessionConfig(id)
	if err != nil {
		_ = handle.Remove()
		_ = dev.Close()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	t.mu.Lock()
	t.cancel = cancel
	t.done = done
	t.dev = dev
	t.handle = handle
	t.iface = dev.Name()
	t.lastErr = ""
	t.mu.Unlock()

	go t.run(ctx, done, tlsConfig, endpoint, quicConfig, api.NewWaterAdapter(dev))
	t.setState(StateConnecting, "")
	return nil
}

// Stop tears the session down and restores the routing table.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	cancel, done, handle, dev := t.cancel, t.done, t.handle, t.dev
	t.cancel, t.done, t.handle, t.dev = nil, nil, nil, nil
	t.iface = ""
	t.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()

	if done != nil {
		select {
		case <-done:
		case <-time.After(pumpShutdownGrace * 2):
			log.Println("tunnel session did not stop within grace period")
		}
	}
	if handle != nil {
		if err := handle.Remove(); err != nil {
			log.Printf("removing routes: %v", err)
		}
	}
	if dev != nil {
		_ = dev.Close()
	}
	t.setState(StateDisconnected, "")
	return nil
}

func (t *Tunnel) setState(state TunnelState, lastErr string) {
	t.mu.Lock()
	if t.cancel == nil && state != StateDisconnected {
		// Start/Stop raced; ignore states for a tunnel that is gone.
		t.mu.Unlock()
		return
	}
	t.state = state
	if lastErr != "" {
		t.lastErr = lastErr
	} else if state == StateConnected {
		t.lastErr = ""
	}
	cb := t.onState
	errMsg := t.lastErr
	t.mu.Unlock()
	if cb != nil {
		cb(state, errMsg)
	}
}

// buildSessionConfig turns the identity into the TLS/QUIC parameters of the
// MASQUE handshake: pinned endpoint certificate + client certificate.
func buildSessionConfig(id *Identity) (*tls.Config, *net.UDPAddr, *quic.Config, error) {
	privKey, err := ParseEcPrivateKey(id.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing device private key: %w", err)
	}
	peerPub, err := ParseEndpointPublicKey(id.EndpointPubKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing endpoint public key: %w", err)
	}
	cert, err := GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating client certificate: %w", err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPub, cert, masqueSNI)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("preparing TLS config: %w", err)
	}

	endpoint, err := selectEndpoint(id)
	if err != nil {
		return nil, nil, nil, err
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}
	return tlsConfig, endpoint, quicConfig, nil
}

// selectEndpoint picks the MASQUE server address, preferring IPv4.
func selectEndpoint(id *Identity) (*net.UDPAddr, error) {
	host := id.EndpointV4
	if host == "" {
		host = id.EndpointV6
	}
	if host == "" {
		return nil, errors.New("registration contains no MASQUE endpoint")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("endpoint %q is not an IP address", host)
	}
	return &net.UDPAddr{IP: ip, Port: 443}, nil
}

// run is the MASQUE supervisor: connect, pump packets in both directions,
// report state, reconnect on loss until the context is cancelled.
func (t *Tunnel) run(ctx context.Context, done chan struct{}, tlsCfg *tls.Config,
	endpoint *net.UDPAddr, quicCfg *quic.Config, dev api.TunnelDevice) {
	defer close(done)

	mtu := 1280
	pool := api.NewNetBuffer(mtu + datagramContextIDHeadroom)

	for ctx.Err() == nil {
		t.setState(StateConnecting, "")

		udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(ctx, tlsCfg, quicCfg, connectURI, endpoint)
		if err == nil && rsp != nil && rsp.StatusCode != 200 {
			err = fmt.Errorf("MASQUE handshake returned %s", rsp.Status)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			t.setState(StateReconnecting, err.Error())
			if !sleepCtx(ctx, reconnectionDelay) {
				return
			}
			continue
		}

		t.setState(StateConnected, "")
		log.Println("connected to MASQUE endpoint", endpoint)

		errCh := make(chan error, 2)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(2)

		// TUN -> MASQUE
		go func() {
			defer wg.Done()
			for {
				if pumpCtx.Err() != nil {
					return
				}
				buf := pool.Get()
				n, err := dev.ReadPacket(buf[datagramContextIDHeadroom:])
				if err != nil {
					pool.Put(buf)
					if pumpCtx.Err() == nil {
						errCh <- fmt.Errorf("reading from tunnel device: %w", err)
					}
					return
				}
				if pumpCtx.Err() != nil {
					pool.Put(buf)
					return
				}
				icmp, err := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
				pool.Put(buf)
				if err != nil {
					errCh <- fmt.Errorf("writing to IP connection: %w", err)
					return
				}
				if len(icmp) > 0 {
					if err := dev.WritePacket(icmp); err != nil {
						errCh <- fmt.Errorf("writing ICMP reply to tunnel device: %w", err)
						return
					}
				}
			}
		}()

		// MASQUE -> TUN
		go func() {
			defer wg.Done()
			for {
				if pumpCtx.Err() != nil {
					return
				}
				packet, err := ipConn.ReadPacketZeroCopy(true)
				if err != nil {
					if pumpCtx.Err() == nil {
						errCh <- fmt.Errorf("reading from IP connection: %w", err)
					}
					return
				}
				if err := dev.WritePacket(packet); err != nil {
					errCh <- fmt.Errorf("writing to tunnel device: %w", err)
					return
				}
			}
		}()

		var lost error
		select {
		case <-ctx.Done():
			lost = ctx.Err()
		case lost = <-errCh:
		}

		cancelPumps()
		_ = ipConn.Close()

		waitDone := make(chan struct{})
		go func() { wg.Wait(); close(waitDone) }()
		select {
		case <-waitDone:
		case <-time.After(pumpShutdownGrace):
			log.Println("pump shutdown grace expired; a reader may still be parked")
		}
		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}

		if ctx.Err() != nil {
			return
		}
		log.Printf("tunnel connection lost: %v", lost)
		t.setState(StateReconnecting, lost.Error())
		if !sleepCtx(ctx, reconnectionDelay) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
