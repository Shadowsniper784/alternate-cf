// Package engine owns the MASQUE session. It runs inside warpaltd because on
// Windows the Wintun adapter can only be used by the process that created it,
// and because on both platforms the dataplane should live next to the routes
// it feeds. The protocol itself is usque's implementation; this file is only
// lifecycle and packet pumping.
package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/tun"

	"warpalt/internal/warp"
)

const (
	// connectURI and connectSNI are the constants usque keeps module-internal.
	// They are part of the Cloudflare MASQUE service contract, not secrets.
	connectURI = "https://cloudflareaccess.com"
	connectSNI = "consumer-masque.cloudflareclient.com"

	defaultMTU = 1280
	keepAlive  = 10 * time.Second
	minBackoff = 2 * time.Second
	maxBackoff = 30 * time.Second
)

// Config is everything a session needs. Identity is the enrolled identity,
// Device is the already-configured TUN interface and OnState receives
// "connecting", "connected", "reconnecting" or "error".
type Config struct {
	Identity *warp.Identity
	Device   tun.Device
	Endpoint string
	MTU      int
	OnState  func(state, detail string)
}

// Run maintains a MASQUE session until ctx is cancelled. It is expected to be
// called once per Connect; returning nil means the tunnel was stopped on
// purpose.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Identity == nil {
		return errors.New("no identity")
	}
	if cfg.Device == nil {
		return errors.New("no tunnel device")
	}
	if cfg.Endpoint == "" {
		return errors.New("no MASQUE endpoint")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	onState := cfg.OnState
	if onState == nil {
		onState = func(string, string) {}
	}

	tlsConfig, err := buildTLS(cfg.Identity)
	if err != nil {
		return err
	}
	endpoint, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("resolving MASQUE endpoint %q: %w", cfg.Endpoint, err)
	}

	adapter := api.NewNetstackAdapter(cfg.Device)
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		onState("connecting", "")
		log.Printf("warpaltd: attempting MASQUE connection to %s", endpoint.String())
		err := session(ctx, adapter, tlsConfig, endpoint, mtu, onState)
		if ctx.Err() != nil {
			log.Printf("warpaltd: connection cancelled: %v", ctx.Err())
			return nil
		}
		if err == nil {
			err = errors.New("session closed")
		}
		log.Printf("warpaltd: MASQUE session lost: %v", err)
		onState("reconnecting", err.Error())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func buildTLS(id *warp.Identity) (*tls.Config, error) {
	priv, err := warp.ParseEcPrivateKey(id.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing device private key: %w", err)
	}
	peer, err := warp.ParseEndpointPublicKey(id.EndpointPubKey)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint public key: %w", err)
	}
	cert, err := warp.GenerateCert(priv, &priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generating client certificate: %w", err)
	}
	tlsConfig, err := api.PrepareTlsConfig(priv, peer, cert, connectSNI)
	if err != nil {
		return nil, fmt.Errorf("preparing TLS config: %w", err)
	}
	return tlsConfig, nil
}

// session establishes one QUIC/Connect-IP session and pumps packets in both
// directions until it fails or ctx is cancelled.
func session(
	ctx context.Context,
	device api.TunnelDevice,
	tlsConfig *tls.Config,
	endpoint *net.UDPAddr,
	mtu int,
	onState func(string, string),
) error {
	quicConfig := &quic.Config{
		EnableDatagrams:         true,
		KeepAlivePeriod:         keepAlive,
		InitialPacketSize:       uint16(mtu),
		DisablePathMTUDiscovery: true,
	}
	log.Printf("warpaltd: calling ConnectTunnel to %s", endpoint.String())
	udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(ctx, tlsConfig, quicConfig, connectURI, endpoint)
	if err != nil {
		log.Printf("warpaltd: ConnectTunnel failed: %v", err)
		return err
	}
	log.Printf("warpaltd: ConnectTunnel returned successfully")

	closeAll := func() {
		if ipConn != nil {
			_ = ipConn.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if tr != nil {
			_ = tr.Close()
		}
		if rsp != nil && rsp.Body != nil {
			_ = rsp.Body.Close()
		}
	}
	defer closeAll()

	if rsp == nil {
		return errors.New("MASQUE connection returned no HTTP response")
	}
	if rsp.StatusCode != 200 {
		return fmt.Errorf("MASQUE endpoint returned %s", rsp.Status)
	}
	log.Printf("warpaltd: MASQUE session established, starting packet pump")
	onState("connected", "")

	pool := api.NewNetBuffer(mtu)
	errCh := make(chan error, 2)

	// Outbound: device -> Connect-IP. A non-fatal write error is logged and
	// the loop continues, mirroring the reference implementation.
	go func() {
		for {
			buf := pool.Get()
			n, err := device.ReadPacket(buf)
			if err != nil {
				pool.Put(buf)
				errCh <- fmt.Errorf("reading TUN: %w", err)
				return
			}
			icmp, err := ipConn.WritePacket(buf[:n])
			pool.Put(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					errCh <- err
					return
				}
				log.Printf("warpaltd: dropping outbound packet: %v", err)
				continue
			}
			if len(icmp) > 0 {
				if err := device.WritePacket(icmp); err != nil {
					errCh <- fmt.Errorf("writing ICMP to TUN: %w", err)
					return
				}
			}
		}
	}()

	// Inbound: Connect-IP -> device.
	go func() {
		buf := pool.Get()
		defer pool.Put(buf)
		for {
			n, err := ipConn.ReadPacket(buf, true)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					errCh <- err
					return
				}
				log.Printf("warpaltd: dropping inbound read: %v", err)
				continue
			}
			if err := device.WritePacket(buf[:n]); err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
					errCh <- fmt.Errorf("writing TUN: %w", err)
					return
				}
				// A single unroutable or malformed packet must not take the
				// whole session down; drop it and keep pumping.
				log.Printf("warpaltd: dropping inbound packet: %v", err)
				continue
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		// A closed connection during shutdown is expected.
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}
