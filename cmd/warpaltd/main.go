// Command warpaltd is the privileged service. It must run as root (Linux
// systemd system unit) or LocalSystem (Windows service). The GUI never runs
// elevated.
package main

import (
	"flag"
	"log"
	"os"

	"warpalt/internal/daemon"
)

func main() {
	var (
		install   bool
		uninstall bool
		console   bool
		verbose   bool
	)
	flag.BoolVar(&install, "install-service", false, "install and start the Windows service (no-op on Unix)")
	flag.BoolVar(&uninstall, "uninstall-service", false, "stop and remove the Windows service (no-op on Unix)")
	flag.BoolVar(&console, "console", false, "run in this console even when launched by the Windows service manager")
	flag.BoolVar(&verbose, "v", false, "log every step to stdout (same as WARPALT_VERBOSE=1)")
	flag.Parse()

	if verbose {
		_ = os.Setenv("WARPALT_VERBOSE", "1")
	}
	if os.Getenv("WARPALT_VERBOSE") != "" {
		log.SetOutput(os.Stdout)
		log.Print("warpaltd: verbose logging to stdout")
	}

	if err := daemon.Main(install, uninstall, console); err != nil {
		log.Fatalf("warpaltd: %v", err)
	}
}
