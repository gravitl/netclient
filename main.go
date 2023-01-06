//go:generate goversioninfo -icon=resources/windows/netclient.ico -manifest=resources/windows/netclient.exe.manifest.xml -64=true -o=netclient.syso

/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"os"
	"runtime"

	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
)

// TODO: use -ldflags to set the right version at build time
var version = "v0.18.0"

var guiFunc = func() {}

func main() {

	ncArgs := os.Args
	if len(ncArgs) > 1 && ncArgs[1] != "gui" ||
		len(ncArgs) == 1 && runtime.GOOS != "windows" { // windows by default uses gui
		config.SetVersion(version)
		cmd.Execute()
	} else {
		guiFunc()
	}
}
