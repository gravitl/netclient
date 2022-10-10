//go:build gui
// +build gui

package main

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/gui"
	"github.com/gravitl/netclient/ncutils"
)

func init() {
	config.GuiActive = true

	config.GuiRun = func() {
		networks, err := ncutils.GetSystemNetworks()
		if err != nil {
			networks = []string{}
		}
		gui.Run(networks)
	}
}
