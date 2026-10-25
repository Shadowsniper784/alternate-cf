package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"warpalt/internal/app"
)

//go:embed all:frontend
var frontendAssets embed.FS

func main() {
	assets, err := fs.Sub(frontendAssets, "frontend")
	if err != nil {
		log.Fatalf("embedding frontend: %v", err)
	}

	application := app.New()

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
