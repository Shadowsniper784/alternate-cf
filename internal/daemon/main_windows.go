//go:build windows

package daemon

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the Windows service name.
const ServiceName = "warpaltd"

// Main runs the daemon as a service or in the console, and handles the
// one-time service installation.
func Main(install, uninstall, console bool) error {
	switch {
	case install:
		return installService()
	case uninstall:
		return uninstallService()
	}

	d := New()
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detecting service context: %w", err)
	}
	if isService && !console {
		return svc.Run(ServiceName, &serviceHandler{d: d})
	}
	return d.Serve()
}

type serviceHandler struct {
	d *Daemon
}

func (h *serviceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	errCh := make(chan error, 1)
	go func() { errCh <- h.d.Serve() }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				_ = h.d.Close()
				select {
				case <-errCh:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case err := <-errCh:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func installService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("opening the service manager (run this elevated): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(ServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("%s is already installed", ServiceName)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating warpaltd.exe: %w", err)
	}
	s, err := m.CreateService(ServiceName, exe, mgr.Config{
		DisplayName:      "warpalt tunnel service",
		Description:      "Owns the Wintun adapter, routes and MASQUE session for the warpalt desktop client.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	})
	if err != nil {
		return fmt.Errorf("creating %s: %w", ServiceName, err)
	}
	defer s.Close()

	// Restart on crash. The daemon is stateless enough that this is safe.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}, 3600)

	if err := s.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", ServiceName, err)
	}
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("opening the service manager (run this elevated): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("%s is not installed", ServiceName)
	}
	defer s.Close()

	// A service that is already stopped is fine; Delete below is the real
	// operation and reports anything that matters.
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 40; i++ {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("deleting %s: %w", ServiceName, err)
	}
	return nil
}
