/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
	app "github.com/gravitl/netclient/gui"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// TODO: use -ldflags to set the right version at build time
var version = "dev"

//go:embed all:gui/frontend/dist
var assets embed.FS

func main() {

	ncArgs := os.Args
	if len(ncArgs) > 1 && ncArgs[1] != "gui" ||
		len(ncArgs) == 1 {
		config.SetVersion(version)
		cmd.Execute()
	} else {
		setupNetclientGui()
	}
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
