/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/config"
)

var version = "dev"

func main() {
	config.SetVersion(version)
	cmd.Execute()
}
