package main

import (
	"embed"
	"log"
	"runtime"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
//go:embed appicon.png

var assets embed.FS

var appIcon = GetFileAsBytes("./appicon.png")

var version = "v0.21.2"

var url = "http://" + functions.DefaultHttpServerAddr + ":" + functions.DefaultHttpServerPort

func main() {
	log.Println("staring netclient gui version: ", version) // temp.. version should be displayed in about dialog
	if runtime.GOOS != "windows" {
		http, err := config.ReadGUIConfig()
		if err != nil {
			logger.FatalLog("error reading gui config", err.Error())
		}
		url = "http://" + http.Address + ":" + http.Port
	}
	// Create an instance of the guiApp structure
	guiApp := NewApp()
	guiApp.GoGetNetclientConfig()
	guiApp.GoGetKnownNetworks()

	// Application menu
	appMenu := GetAppMenu(guiApp)

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
		Linux: &linux.Options{
			Icon: appIcon,
		},
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Icon:    appIcon,
				Title:   "Netclient",
				Message: "It manages WireGuard® so you don't have to",
			},
		},
	}

	// Create application with options
	err := wails.Run(appOptions)

	if err != nil {
		println("Error:", err.Error())
	}
}
