//go:build !windows

package daemon

import (
	"os"
	"path/filepath"

	"warpalt/internal/warp"
)

// stateFile is where the daemon persists its copy of the identity. Root uses
// the system state directory; a console run as a normal user falls back to the
// user config directory so development works without root.
func stateFile() (string, error) {
	if p := os.Getenv("WARPALT_STATE"); p != "" {
		return p, nil
	}
	dir := "/var/lib/warpalt"
	if os.Geteuid() != 0 {
		base, err := warp.Dir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "daemon")
	}
	return filepath.Join(dir, "identity.json"), nil
}

// seal is a no-op on Unix: the file is 0600 and lives in a root-only
// directory, which is the platform's protection model.
func seal(plain []byte) ([]byte, error) { return plain, nil }

func unseal(sealed []byte) ([]byte, error) { return sealed, nil }
