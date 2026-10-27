package routes

import "fmt"

// RouteHandle represents installed routes that can be removed.
type RouteHandle interface {
	Remove() error
}

// RouteApply installs the plan on the platform. It is a thin pointer-friendly
// wrapper so callers that hold a *Plan (for example decoded RPC requests) do
// not have to dereference it themselves.
func RouteApply(plan *Plan, tunIface string) (RouteHandle, error) {
	if plan == nil {
		return nil, fmt.Errorf("routes: nil plan")
	}
	return Apply(*plan, tunIface)
}
