//go:build !linux && !windows

package warp

import (
	"errors"

	"github.com/songgao/water"
)

// createTUN reports that warpalt only implements Linux and Windows.
func createTUN(id *Identity) (*water.Interface, error) {
	return nil, errors.New("warpalt supports linux and windows only")
}
