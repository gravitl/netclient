//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package cmd

import (
	"log"
	"strconv"

	"github.com/gravitl/netclient/ncutils"
)

// checkUID - Checks to make sure user has root privileges
func checkUID() {
	// start our application
	out, err := ncutils.RunCmd("id -u", true)
	if err != nil {
		log.Fatal(out, err)
	}
	id, err := strconv.Atoi(string(out[:len(out)-1]))
	if err != nil {
		log.Fatal(err)
	}
	if id != 0 {
		log.Fatal("This program must be run with elevated privileges. Please re-run with sudo or as root.")
	}
}
