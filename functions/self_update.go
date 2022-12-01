package functions

import (
	"log"
	"strings"

	"github.com/blang/semver"
	"github.com/gravitl/netclient/daemon"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// SelfUpdate updates the netclient binary in place to the latest release available on GitHub
// and reboots the daemon if update is successful
// All binary names must adhere to the format `netclient-{platform}-{architecture}`
func SelfUpdate(currentVersion string) {
	if currentVersion == "dev" {
		return
	}
	semVer := strings.Replace(currentVersion, "v", "", -1)
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
