package gui

import (
	"context"
	"fmt"
	"strings"

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

// App.Startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

// GetAppMenu builds and returns the application menu
func GetAppMenu(app *App) *menu.Menu {
	menu := menu.NewMenu()

	fileMenu := menu.AddSubmenu("File")
	fileMenu.AddText("Networks", nil, app.openNetworksPage)
	fileMenu.AddText("Host Settings", nil, app.openSettingsPage)
	fileMenu.AddText("Uninstall", nil, app.uninstallApp)

	aboutMenu := menu.AddSubmenu("About")
	aboutMenu.AddText("Docs", &keys.Accelerator{Key: "f1"}, app.openDocs)

	return menu
}

// openDocs opens the Netmaker docs in user's browser
func (a *App) openDocs(callbackData *menu.CallbackData) {
	err := OpenUrlInBrowser(NETMAKER_DOCS_LINK)
	if err != nil {
		a.GoOpenDialogue(runtime.ErrorDialog, "An error occured whiles opening docs.\n"+err.Error(), "Error opening docs")
	}
}

func (a *App) openNetworksPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(a.ctx, EV_OPEN_NETWORKS_PAGE)
}

func (a *App) openSettingsPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(a.ctx, EV_OPEN_SETTINGS_PAGE)
}

func (a *App) uninstallApp(callbackData *menu.CallbackData) {
	res, err := a.GoOpenDialogue(runtime.QuestionDialog, "Do you want to uninstall Netclient?", "Unintstall?")
	if err != nil {
		return
	}
	fmt.Println(res)
	if res != "Yes" {
		return
	}

	errs, err := functions.Uninstall()
	if err != nil {
		var errString strings.Builder
		for _, err := range errs {
			errString.WriteString(err.Error() + ", ")
		}

		a.GoOpenDialogue(runtime.ErrorDialog, "An error occured whiles uninstalling.\n"+errString.String(), "Error unintstalling")
	}
}
