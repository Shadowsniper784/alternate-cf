//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpalt/internal/control"
	"warpalt/internal/protocol"
	"warpalt/internal/warp"
)

func testIdentity() warp.Identity {
	return warp.Identity{
		Team:           "example",
		PrivateKey:     "a2V5",
		EndpointPubKey: "cHVi",
		EndpointV4:     "162.159.192.1",
		IPv4:           "172.16.0.2",
		DeviceID:       "device-1",
		DeviceName:     "test-device",
	}
}

func TestControlRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("WARPALT_SOCKET", filepath.Join(dir, "control.sock"))
	t.Setenv("WARPALT_STATE", filepath.Join(dir, "identity.json"))

	d := New()
	errCh := make(chan error, 1)
	go func() { errCh <- d.Serve() }()

	// Wait for the socket to appear rather than assuming immediate readiness.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "control.sock")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket did not appear")
		}
		time.Sleep(20 * time.Millisecond)
	}

	ping, err := control.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if ping.Version != protocol.Version {
		t.Errorf("Ping version = %d, want %d", ping.Version, protocol.Version)
	}

	status, err := control.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Enrolled || status.State != "disconnected" {
		t.Errorf("unexpected initial status: %+v", status)
	}

	id := testIdentity()
	status, err = control.PutIdentity(id)
	if err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}
	if !status.Enrolled || status.Team != id.Team || status.DeviceID != id.DeviceID {
		t.Errorf("identity not reflected in status: %+v", status)
	}

	info, err := control.GetIdentity()
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if !info.Enrolled || info.Team != id.Team {
		t.Errorf("GetIdentity = %+v", info)
	}

	// Connect must fail cleanly without root/CAP_NET_ADMIN instead of
	// crashing or leaving the daemon wedged.
	if os.Geteuid() != 0 {
		_, err := control.Connect(protocol.ConnectRequest{
			Identity: id,
			Endpoint: "162.159.192.1:443",
		})
		if err == nil {
			t.Error("Connect without privileges should fail")
			_, _ = control.Disconnect()
		}
		status, serr := control.Status()
		if serr != nil {
			t.Fatalf("Status after failed connect: %v", serr)
		}
		if status.State != "error" {
			t.Errorf("state after failed connect = %q, want error", status.State)
		}
	}

	status, err = control.Logout()
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if status.Enrolled {
		t.Errorf("still enrolled after logout: %+v", status)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not stop")
	}
}
