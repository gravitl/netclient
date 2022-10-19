/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"github.com/gravitl/netclient/cmd"
	"github.com/gravitl/netclient/ncutils"
)

var version = "dev"

func main() {
	ncutils.SetVersion(version)
	cmd.Execute()
}
