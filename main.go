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
	"github.com/gravitl/netclient/daemon"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// TODO: use -ldflags to set the right version at build time
var version = "v0.18.0"

var guiFunc = func() {}

func autoUpdate() {
	semVer := strings.Replace(version, "v", "", -1)
	v := semver.MustParse(semVer)
	latest, err := selfupdate.UpdateSelf(v, "gravitl/netmaker")
	if err != nil {
		log.Println("Binary update failed:", err)
		return
	}
	if !latest.Version.Equals(v) {
		log.Println("Successfully updated to version", latest.Version)
		log.Println("Release notes:\n", latest.ReleaseNotes)
		// reboot daemon
		if err := daemon.Stop(); err != nil {
			log.Println("Error encountered while stopping daemon:", err)
			return
		}
		if err := daemon.InstallDaemon(); err != nil {
			log.Println("Error encountered while installing daemon:", err)
			return
		}
		if err := daemon.Start(); err != nil {
			log.Println("Error encountered while starting daemon:", err)
			return
		}
	}
}

func main() {

	ncArgs := os.Args
	if len(ncArgs) > 1 && ncArgs[1] != "gui" ||
		len(ncArgs) == 1 && runtime.GOOS != "windows" { // windows by default uses gui
		config.SetVersion(version)
		if version != "dev" {
			autoUpdate()
		}
		cmd.Execute()
	} else {
		guiFunc()
	}
}
