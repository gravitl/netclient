//go:build gui
// +build gui

package main

import (
	"fmt"

	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
	app "github.com/gravitl/netclient/gui"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

func init() {
	guiFunc = setupNetclientGui
}

func setupNetclientGui() {
	cmd.InitConfig()
	config.SetVersion(version)
	fmt.Printf("wails: netclient version set to: %s\n", version)

	// Create an instance of the guiApp structure
	guiApp := app.NewApp()

	// Application menu
	appMenu := app.GetAppMenu(guiApp)

	// Application options
	appOptions := &options.App{
		Title:            "Netclient",
		Width:            1024,
		Height:           768,
		MinWidth:         1024,
		MinHeight:        768,
		BackgroundColour: &options.RGBA{R: 0, G: 0, B: 0, A: 1},
		OnStartup:        guiApp.Startup,
		Menu:             appMenu,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Bind: []interface{}{
			guiApp,
		},
	}

	// Create application with options
	err := wails.Run(appOptions)

	if err != nil {
		println("Error:", err.Error())
	}
}
