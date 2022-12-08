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
		guiFunc()
	}
}

var guiFunc = func() { fmt.Println("netclient is headless") }
