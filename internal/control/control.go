// Package control is the unprivileged side of the warpaltd control channel.
// It dials the platform endpoint, performs a JSON-RPC call and closes again;
// the calls are small and infrequent enough that a fresh connection is simpler
// and more robust than keeping a session alive across service restarts.
package control

import (
	"fmt"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"time"

	"warpalt/internal/protocol"
	"warpalt/internal/routes"
	"warpalt/internal/warp"
)

func init() {
	if os.Getenv("WARPALT_VERBOSE") != "" {
		fmt.Fprintln(os.Stdout, "[warpalt] verbose control-plane logging on")
	}
}

const callTimeout = 4 * time.Second

// ErrUnavailable is returned when the service is not installed or not running.
var ErrUnavailable = errUnavailable

// verbose controls whether the GUI logs every failed control-plane call to its
// stdout. It is intended for the stuck-on-loading diagnostic path: when the app
// just sits there, the user can run it with WARPALT_VERBOSE=1 and see a line
// for every status/policy attempt and why it failed.
var verbose = os.Getenv("WARPALT_VERBOSE") != ""

func logVerbose(format string, args ...any) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stdout, "[warpalt] "+format+"\n", args...)
}

func call(method string, args, reply any) error {
	conn, err := dial(callTimeout)
	if err != nil {
		logVerbose("dial %s failed: %v", method, err)
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	client := rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn))
	defer client.Close()
	err = client.Call(protocol.ServiceName+"."+method, args, reply)
	if err != nil {
		logVerbose("RPC %s failed: %v", method, err)
	}
	return err
}

// Status returns the daemon's current snapshot.
func Status() (protocol.Status, error) {
	var out protocol.Status
	err := call("Status", struct{}{}, &out)
	return out, err
}

// Ping checks that the service is reachable and speaks a compatible version.
func Ping() (protocol.Ping, error) {
	var out protocol.Ping
	err := call("Ping", struct{}{}, &out)
	return out, err
}

// Connect brings the tunnel up with the supplied identity and plan.
func Connect(req protocol.ConnectRequest) (protocol.Status, error) {
	var out protocol.Status
	err := call("Connect", req, &out)
	return out, err
}

// Disconnect tears the tunnel down (idempotent).
func Disconnect() (protocol.Status, error) {
	var out protocol.Status
	err := call("Disconnect", struct{}{}, &out)
	return out, err
}

// UpdatePlan replaces the plan of a live tunnel.
func UpdatePlan(plan routes.Plan, mode string) (protocol.Status, error) {
	var out protocol.Status
	err := call("UpdatePlan", protocol.UpdatePlanRequest{Plan: plan, Mode: mode}, &out)
	return out, err
}

// PutIdentity hands the enrolled identity to the daemon so it can persist it
// for later connects.
func PutIdentity(id warp.Identity) (protocol.Status, error) {
	var out protocol.Status
	err := call("PutIdentity", id, &out)
	return out, err
}

// Logout removes the daemon-side identity and tears the tunnel down.
func Logout() (protocol.Status, error) {
	var out protocol.Status
	err := call("Logout", struct{}{}, &out)
	return out, err
}

// GetIdentity returns the redacted identity held by the daemon.
func GetIdentity() (protocol.IdentityInfo, error) {
	var out protocol.IdentityInfo
	err := call("GetIdentity", struct{}{}, &out)
	return out, err
}
