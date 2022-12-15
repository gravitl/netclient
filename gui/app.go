package gui

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"time"

	"fyne.io/systray"
	"github.com/gravitl/netclient/functions"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var appAssets *embed.FS

var SysTrayReadyFunc func()
var SysTrayExitFunc func()

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
func (app *App) Startup(ctx context.Context) {
	app.ctx = ctx
	if SysTrayReadyFunc != nil {
		SysTrayReadyFunc()
	}
}

// App.Shutdown performs cleanup duties when the app is exiting
func (app *App) Shutdown(ctx context.Context) {
	app.ctx = ctx
	if SysTrayExitFunc != nil {
		SysTrayExitFunc()
	}
}

// GetAppMenu builds and returns the application menu
func GetAppMenu(app *App) *menu.Menu {
	menu := menu.NewMenu()

	fileMenu := menu.AddSubmenu("File")
	fileMenu.AddText("Networks", nil, app.openNetworksPage)
	fileMenu.AddText("Netclient Logs", nil, app.openLogsPage)
	fileMenu.AddText("Uninstall", nil, app.uninstallApp)

	aboutMenu := menu.AddSubmenu("About")
	aboutMenu.AddText("Docs", &keys.Accelerator{Key: "f1"}, app.openDocs)

	return menu
}

// openDocs opens the Netmaker docs in user's browser
func (app *App) openDocs(callbackData *menu.CallbackData) {
	err := OpenUrlInBrowser(NETMAKER_DOCS_LINK)
	if err != nil {
		app.GoOpenDialogue(runtime.ErrorDialog, "An error occured whiles opening docs.\n"+err.Error(), "Error opening docs")
	}
}

func (app *App) openNetworksPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(app.ctx, EV_OPEN_NETWORKS_PAGE)
}

func (app *App) openLogsPage(callbackData *menu.CallbackData) {
	runtime.EventsEmit(app.ctx, EV_OPEN_LOGS_PAGE)
}

func (app *App) uninstallApp(callbackData *menu.CallbackData) {
	res, err := app.GoOpenDialogue(runtime.QuestionDialog, "Do you want to uninstall Netclient?", "Unintstall?")
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

		app.GoOpenDialogue(runtime.ErrorDialog, "An error occured whiles uninstalling.\n"+errString.String(), "Error unintstalling")
	}
}

func (app *App) OnSysTrayReady() {
	appIconBytes, err := appAssets.ReadFile(APP_ICON_FILE_PATH)
	if err != nil {
		return
	}

	// menu items for each network
	menuNetworkItems := make([]*NetworkMenuItem, 0)
	var quitMenu *systray.MenuItem = &systray.MenuItem{}

	// show networks status
	go func() {
		systray.SetIcon(appIconBytes)
		systray.SetTitle(APP_NAME)
		systray.SetTooltip(APP_NAME)

		networks, err := app.GoGetKnownNetworks()
		if err != nil {
			return
		}

		for {
			time.Sleep(1000 * time.Millisecond)
			systray.ResetMenu()

			menuNetworkItems = make([]*NetworkMenuItem, 0)
			for i, network := range networks {
				// TODO: find a way to sort by most networks
				// show only top 3 networks so the list is not ridiculously long
				if i > 2 {
					break
				}

				networkName := network.Node.Network
				tooltip := "Click to connect"
				if network.Node.Connected {
					networkName = "✓ " + networkName
					tooltip = "Click to disconnect"
				}

				networkMenuItem := &NetworkMenuItem{
					NetworkName: networkName,
					MenuItem:    systray.AddMenuItemCheckbox(networkName, tooltip, network.Node.Connected),
				}
				menuNetworkItems = append(menuNetworkItems, networkMenuItem)
			}

			systray.AddSeparator()
			quitMenu = systray.AddMenuItem("Quit", "Quit the app")
		}
	}()

	go func() {
		// TODO: len(menuNetworkItems) can change anytime in the app. handle it
		// register on-click handlers
		if len(menuNetworkItems) == 0 {
			for {
				select {
				case <-quitMenu.ClickedCh:
					systray.Quit()
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
		} else {
			for i := 0; true; i++ {
				if i >= len(menuNetworkItems) {
					i = 0
				}

				select {
				case <-quitMenu.ClickedCh:
					systray.Quit()
					return
				case <-menuNetworkItems[i].MenuItem.ClickedCh:
					menu := menuNetworkItems[i]
					if menu.MenuItem.Checked() {
						_, err := app.GoDisconnectFromNetwork(menu.NetworkName)
						if err != nil {
							return
						}
						menu.MenuItem.Uncheck()
					} else {
						_, err := app.GoConnectToNetwork(menu.NetworkName)
						if err != nil {
							return
						}
						menu.MenuItem.Check()
					}
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
		}
	}()
}

func (app *App) OnSysTrayExit() {
}

func (app *App) SetupSysTray() (func(), func()) {
	return systray.RunWithExternalLoop(app.OnSysTrayReady, app.OnSysTrayExit)
}

// func (app *App) SetupSysTray() {
// 	systray.Run(app.OnSysTrayReady, app.OnSysTrayExit)
// }

// HookAppAssets provides a reference to the application's assets
func HookAppAssets(asset *embed.FS) {
	appAssets = asset
}
