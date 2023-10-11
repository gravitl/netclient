package daemon

import (
	"errors"
	"log"
	"os"
	"syscall"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

const MacServiceName = "com.gravitl.netclient"
const MacExecDir = "/usr/local/bin/"

// install- Creates a daemon service from the netclient under LaunchAgents for MacOS
func install() error {
	stop()
	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	if ncutils.FileExists(MacExecDir + "netclient") {
		os.Remove(MacExecDir + "netclient")
		logger.Log(0, "updating netclient binary in", MacExecDir)
	}
	if err := ncutils.Copy(binarypath, MacExecDir+"netclient"); err != nil {
		logger.Log(0, err.Error())
		return err
	}
	if err := createMacService(MacServiceName); err != nil {
		return err
	}
	return start()
}

func start() error {
	if _, err := ncutils.RunCmd("launchctl load /Library/LaunchDaemons/"+MacServiceName+".plist", true); err != nil {
		return err
	}
	return nil
}

// stop - stop launch daemon
func stop() error {
	if _, err := ncutils.RunCmd("launchctl unload  /Library/LaunchDaemons/"+MacServiceName+".plist", true); err != nil {
		return err
	}
	return nil
}

func hardRestart() error {
	if _, err := ncutils.RunCmd("launchctl kickstart -k system/"+MacServiceName+" /Library/LaunchDaemons/"+MacServiceName+".plist", true); err != nil {
		return err
	}
	return nil
}

// cleanUp - Removes the netclient checkin daemon from LaunchDaemons
func cleanUp() error {
	var faults bool
	if _, err := ncutils.RunCmd("launchctl unload /Library/LaunchDaemons/"+MacServiceName+".plist", true); err != nil {
		faults = true
		// manually kill the daemon
		signalDaemon(syscall.SIGTERM)
	}
	if ncutils.FileExists("/Library/LaunchDaemons/" + MacServiceName + ".plist") {
		if err := os.Remove("/Library/LaunchDaemons/" + MacServiceName + ".plist"); err != nil {
			faults = true
			logger.Log(1, err.Error())
		}
	}
	if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
		faults = true
	}
	if err := os.Remove(MacExecDir + "netclient"); err != nil {
		faults = true
	}
	if faults {
		return errors.New("errors were encountered removing launch daemons")
	}
	return nil
}

// createMacService - Creates the mac service file for LaunchDaemons
func createMacService(servicename string) error {
	_, err := os.Stat("/Library/LaunchDaemons")
	if os.IsNotExist(err) {
		os.Mkdir("/Library/LaunchDaemons", 0755)
	} else if err != nil {
		log.Println("couldnt find or create /Library/LaunchDaemons")
		return err
	}
	daemonstring := macDaemonString()
	daemonbytes := []byte(daemonstring)

	if !ncutils.FileExists("/Library/LaunchDaemons/com.gravitl.netclient.plist") {
		err = os.WriteFile("/Library/LaunchDaemons/com.gravitl.netclient.plist", daemonbytes, 0644)
	}
	return err
}

// macDaemonString - the file contents for the mac netclient daemon service (launchdaemon)
func macDaemonString() string {
	return `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\" >
<plist version='1.0'>
<dict>
	<key>Label</key><string>com.gravitl.netclient</string>
	<key>ProgramArguments</key>
		<array>
			<string>/usr/local/bin/netclient</string>
			<string>daemon</string>
		</array>
	<key>StandardOutPath</key><string>/var/log/com.gravitl.netclient.log</string>
	<key>StandardErrorPath</key><string>/var/log/com.gravitl.netclient.log</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>AbandonProcessGroup</key><true/>
	<key>EnvironmentVariables</key>
		<dict>
			<key>PATH</key>
			<string>/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
		</dict>
</dict>
</plist>
`
}

// MacTemplateData - struct to represent the mac service
type MacTemplateData struct {
	Label    string
	Interval string
}

// GetInitType - returns the init type (not applicable for darwin)
func GetInitType() config.InitType {
	return config.UnKnown
}
