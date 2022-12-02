package main

import (
	"embed"
	"fmt"

	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// TODO: use -ldflags to set the right version at build time
var NETCLIENT_VERSION = "dev"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	setupNetclient()

	// Create an instance of the app structure
	app := NewApp()

	// Application menu
	appMenu := getAppMenu(app)

	// Application options
	appOptions := &options.App{
		Title:            "NetClient",
		Width:            1024,
		Height:           768,
		MinWidth:         1024,
		MinHeight:        768,
		BackgroundColour: &options.RGBA{R: 0, G: 0, B: 0, A: 1},
		OnStartup:        app.startup,
		Menu:             appMenu,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Bind: []interface{}{
			app,
		},
	}

	// Create application with options
	err := wails.Run(appOptions)

	if err != nil {
		println("Error:", err.Error())
	}
}

func setupNetclient() {
	cmd.InitConfig()
	config.SetVersion(NETCLIENT_VERSION)
	fmt.Printf("wails: netclient version set to: %s\n", NETCLIENT_VERSION)
}
