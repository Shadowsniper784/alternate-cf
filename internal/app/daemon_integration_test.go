//go:build !windows

package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpalt/internal/control"
	"warpalt/internal/daemon"
	"warpalt/internal/warp"
)

func TestStatusFromDaemon(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	t.Setenv("WARPALT_SOCKET", socket)
	t.Setenv("WARPALT_STATE", filepath.Join(dir, "identity.json"))
	t.Setenv("XDG_CONFIG_HOME", dir)

	d := daemon.New()
	errCh := make(chan error, 1)
	go func() { errCh <- d.Serve() }()
	defer func() {
		_ = d.Close()
		<-errCh
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	id := warp.Identity{
		Team:           "example",
		PrivateKey:     "a2V5",
		EndpointPubKey: "cHVi",
		EndpointV4:     "162.159.192.1",
		IPv4:           "172.16.0.2",
		DeviceName:     "test",
		DeviceID:       "device-1",
	}
	if _, err := control.PutIdentity(id); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}

	a := New()
	st := a.GetStatus()
	if !st.Enrolled {
		t.Fatalf("daemon identity not reflected: %+v", st)
	}
	if st.Team != id.Team || st.DeviceName != id.DeviceName {
		t.Errorf("status fields = %+v", st)
	}
	if st.State != "disconnected" {
		t.Errorf("state = %q, want disconnected", st.State)
	}
	if st.LastError != "" {
		t.Errorf("unexpected error: %q", st.LastError)
	}
}
