package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"warpalt/internal/app"
)

//go:embed all:frontend
var frontendAssets embed.FS

func main() {
	// Must run before the first WebView exists: without it GTK's unset DPI
	// sentinel makes WebKitGTK scale the page by -1/96 and the window renders
	// as a super-thin column.
	fixGTKDPI()

	// Verbose mode: every diagnostic (GUI, control plane, frontend) goes to
	// stdout so `WARPALT_VERBOSE=1 ./warpalt` shows why the window is stuck.
	verbose := os.Getenv("WARPALT_VERBOSE") != ""
	if verbose {
		log.SetOutput(os.Stdout)
		fmt.Fprintln(os.Stdout, "[warpalt] verbose logging enabled")
	}

	assets, err := fs.Sub(frontendAssets, "frontend")
	if err != nil {
		log.Fatalf("embedding frontend: %v", err)
	}

	application := app.New()

	if verbose {
		fmt.Fprintln(os.Stdout, "[warpalt] starting wails runtime")
	}

	err = wails.Run(&options.App{
		Title:     "warpalt — Cloudflare One client",
		Width:     1020,
		Height:    740,
		MinWidth:  760,
		MinHeight: 540,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 18, G: 20, B: 24, A: 1},
		OnStartup:        application.Startup,
		OnShutdown:       application.Shutdown,
		Bind:             []any{application},
	})
	if err != nil {
		log.Fatal(err)
	}
}
