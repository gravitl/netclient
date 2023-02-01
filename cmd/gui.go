//go:build !headless
// +build !headless

/*
Copyright © 2023 Netmaker Team <info@netmaker.io>
*/

package cmd

import (
	app "github.com/gravitl/netclient/gui"
	assets "github.com/gravitl/netclient/gui/frontend"
	"github.com/spf13/cobra"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

var appIcon = app.GetFileAsBytes("./build/appicon.png")

// guiCmd represents the gui command
var guiCmd = &cobra.Command{
	Use:   "gui",
	Args:  cobra.ExactArgs(0),
	Short: "start the netclient GUI",
	Long: `utilize the netclient Graphical User Interface (aka. GUI)
For example:

netclient gui`,
	Run: func(cmd *cobra.Command, args []string) {
		gui()
	},
}

func init() {
	rootCmd.AddCommand(guiCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// connectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// connectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func gui() {
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
			Assets: assets.Assets,
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
