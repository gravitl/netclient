package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// App.Startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

// GetAppMenu builds and returns the application menu
func GetAppMenu(app *App) *menu.Menu {
	appMenu := menu.NewMenu()

	fileMenu := appMenu.AddSubmenu("File")
	fileMenu.AddText("Networks", nil, app.openNetworksPage)
	fileMenu.AddText("Host Settings", nil, app.openSettingsPage)
	fileMenu.AddText("Uninstall", nil, app.uninstallApp)

	aboutMenu := appMenu.AddSubmenu("About")
	aboutMenu.AddText("Docs", &keys.Accelerator{Key: "f1"}, app.openDocs)

	// on macos platform, we should append EditMenu to enable Cmd+C,Cmd+V,Cmd+Z... shortcut
	if runtime.GOOS == "darwin" {
		appMenu.Append(menu.EditMenu())
	}

	return appMenu
}

// openDocs opens the Netmaker docs in user's browser
func (a *App) openDocs(callbackData *menu.CallbackData) {
	err := OpenUrlInBrowser(NETMAKER_DOCS_LINK)
	if err != nil {
		a.GoOpenDialogue(wailsRuntime.ErrorDialog, "An error occured whiles opening docs.\n"+err.Error(), "Error opening docs")
	}
}

func (a *App) openNetworksPage(callbackData *menu.CallbackData) {
	wailsRuntime.EventsEmit(a.ctx, EV_OPEN_NETWORKS_PAGE)
}

func (a *App) openSettingsPage(callbackData *menu.CallbackData) {
	wailsRuntime.EventsEmit(a.ctx, EV_OPEN_SETTINGS_PAGE)
}

func (a *App) uninstallApp(callbackData *menu.CallbackData) {
	res, err := a.GoOpenDialogue(wailsRuntime.QuestionDialog, "Do you want to uninstall Netclient?", "Unintstall?")
	if err != nil {
		return
	}
	fmt.Println(res)
	if res != "Yes" {
		return
	}
	if _, err := a.GoUninstall(); err != nil {
		a.GoOpenDialogue(wailsRuntime.InfoDialog, "Uninstalling steps/errors.\n"+err.Error(), "Netclient uninstallation")
	}
	os.Exit(0)
}
