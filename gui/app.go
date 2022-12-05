package main

import (
	"context"

	"github.com/gravitl/netclient/functions"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// getAppMenu builds and returns the application menu
func getAppMenu(app *App) *menu.Menu {
	menu := menu.NewMenu()

	fileMenu := menu.AddSubmenu("File")
	fileMenu.AddText("Networks", nil, app.openNetworksPage)
	fileMenu.AddText("Server Logs", nil, app.openServerLogsPage)
	fileMenu.AddText("Uninstall", nil, app.uninstallApp)

	aboutMenu := menu.AddSubmenu("About")
	aboutMenu.AddText("Docs", &keys.Accelerator{Key: "f1"}, app.openDocs)

	return menu
}

// openDocs opens the Netmaker docs in user's browser
func (a *App) openDocs(callbackData *menu.CallbackData) {
	OpenUrlInBrowser(NETMAKER_DOCS_LINK)
}

func (a *App) openNetworksPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(a.ctx, EV_OPEN_NETWORKS_PAGE)
}

func (a *App) openServerLogsPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(a.ctx, EV_OPEN_SERVER_LOGS_PAGE)
}

func (a *App) uninstallApp(callbackData *menu.CallbackData) {
	// TODO: notify
	functions.Uninstall()
}
