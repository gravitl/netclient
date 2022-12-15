// this file contains types to serve as wrappers since wails supports only
// up to two function return values: (data, error) or (data)
// https://wails.io/docs/howdoesitwork#method-binding:~:text=The%20generated%20methods,passed%20to%20it.
package gui

import (
	"fyne.io/systray"
	"github.com/gravitl/netclient/config"
)

// Network describes a server netclient is connected to
// as well as nc itself's representation on a network
type Network struct {
	Node   *config.Node   `json:"node"`
	Server *config.Server `json:"server"`
}

// NetworkMenuItem is network name and menu item pair
type NetworkMenuItem struct {
	NetworkName string
	MenuItem    *systray.MenuItem
}
