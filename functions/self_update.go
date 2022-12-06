package functions

import (
	"strings"
	"unicode"

	"github.com/blang/semver"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// SelfUpdate updates the netclient binary in place to the latest release available on GitHub
// and reboots the daemon if update is successful
// All binary names must adhere to the format `netclient-{platform}-{architecture}`
func SelfUpdate(currentVersion string, rebootDaemon bool) {
	if currentVersion == "dev" {
		return
	}
	semVer := strings.TrimFunc(currentVersion, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	v := semver.MustParse(semVer)
	latest, err := selfupdate.UpdateSelf(v, "gravitl/netclient")
	if err != nil {
		logger.Log(0, "Binary update failed:", err.Error())
		return
	}
	if !latest.Version.Equals(v) {
		logger.Log(0, "Successfully updated to version", latest.Version.String())
		logger.Log(0, "Release notes:\n", latest.ReleaseNotes)
		if !rebootDaemon {
			return
		}
		// reboot daemon
		if err := daemon.Stop(); err != nil {
			logger.Log(0, "Error encountered while stopping daemon:", err.Error())
			return
		}
		if err := daemon.Install(); err != nil {
			logger.Log(0, "Error encountered while installing daemon:", err.Error())
			return
		}
		if err := daemon.Start(); err != nil {
			logger.Log(0, "Error encountered while starting daemon:", err.Error())
			return
		}
	}
}
