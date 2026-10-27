//go:build windows

package control

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

var errUnavailable = errors.New("warpaltd is not running")

// Endpoint names the control channel endpoint for log lines.
func Endpoint() string { return PipeName() }

// PipeName is the named pipe the service listens on. The environment override
// exists for development and for tests.
func PipeName() string {
	if p := os.Getenv("WARPALT_PIPE"); p != "" {
		return p
	}
	return `\\.\pipe\warpalt-control`
}

func dial(timeout time.Duration) (net.Conn, error) {
	c, err := winio.DialPipe(PipeName(), &timeout)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrUnavailable, PipeName(), err)
	}
	return c, nil
}
