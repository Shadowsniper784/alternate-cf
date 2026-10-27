//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"

	"warpalt/internal/warp"
)

func main() {
	// Simple WireGuard client stub
	// In production, this would implement the full WireGuard protocol

	fmt.Println("WireGuard client stub")
	fmt.Println("Usage: wireguard connect <config>")

	if len(os.Args) < 2 {
		fmt.Println("Please provide a WireGuard config file")
		os.Exit(1)
	}

	configFile := os.Args[1]
	profile, err := warp.ParseWgProfile(configFile)
	if err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Interface:\n")
	fmt.Printf("  PrivateKey: %s\n", profile.PrivateKey)
	fmt.Printf("  Address: %s\n", profile.Address1)
	fmt.Printf("  DNS: 1.1.1.1\n")
	fmt.Printf("Peer:\n")
	fmt.Printf("  PublicKey: %s\n", profile.PublicKey)
	fmt.Printf("  Endpoint: %s\n", profile.Endpoint)
	fmt.Printf("  AllowedIPs: 0.0.0.0/0\n")

	if profile.Keepalive > 0 {
		fmt.Printf("  PersistentKeepalive: %d\n", profile.Keepalive)
	}

	fmt.Println("\nWireGuard connection established (stub)")
}
