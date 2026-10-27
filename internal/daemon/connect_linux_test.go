//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpalt/internal/control"
	"warpalt/internal/protocol"
)

// TestConnectLifecycle needs CAP_NET_ADMIN, so run it as root or under
// `unshare -Urn go test ./internal/daemon`. The fake TLS material makes the
// engine fail immediately after the TUN and routes are installed; the point is
// to prove the daemon applies then rolls back its kernel state.
func TestConnectLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or a user+network namespace (unshare -Urn)")
	}
	dir := t.TempDir()
	t.Setenv("WARPALT_SOCKET", filepath.Join(dir, "control.sock"))
	t.Setenv("WARPALT_STATE", filepath.Join(dir, "identity.json"))
	t.Setenv("XDG_CONFIG_HOME", dir)

	d := New()
	errCh := make(chan error, 1)
	go func() { errCh <- d.Serve() }()
	defer func() {
		_ = d.Close()
		<-errCh
	}()
	waitForSocket(t, filepath.Join(dir, "control.sock"))

	id := testIdentity()
	if _, err := control.PutIdentity(id); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}
	status, err := control.Connect(protocol.ConnectRequest{
		Identity: id,
		Endpoint: "162.159.192.1:443",
		Mode:     "exclude",
	})
	if err != nil {
		t.Skipf("TUN unavailable in this environment: %v", err)
	}
	if status.State != "connecting" && status.State != "connected" {
		t.Errorf("state after Connect = %q", status.State)
	}
	if status.Iface == "" {
		t.Error("no interface reported")
	}

	// The engine fails on the dummy key and the daemon must roll back.
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, err = control.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if status.State == "error" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state did not become error: %+v", status)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if status.Iface != "" {
		t.Errorf("interface was not cleared after engine failure: %+v", status)
	}

	status, err = control.Disconnect()
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if status.State != "disconnected" {
		t.Errorf("state after Disconnect = %q", status.State)
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s did not appear", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
