//go:generate goversioninfo -icon=resources/windows/netclient.ico -manifest=resources/windows/netclient.exe.manifest.xml -64=true -o=netclient.syso

/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
)

// TODO: use -ldflags to set the right version at build time
var version = "v1.5.0"

func main() {
	config.SetVersion(version)
	cmd.Execute()
}
