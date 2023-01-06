//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package config

import (
	"log"
	"os/user"
)

// checkUID - Checks to make sure user has root privileges
func checkUID() {
	// start our application
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	if user.Username != "root" {
		log.Fatal("This program must be run with elevated privileges. Please re-run with sudo or as root.")
	}
}
