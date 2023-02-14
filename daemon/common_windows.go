package daemon

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

// install - sets up the Windows daemon service
func install() error {
	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(binarypath)
	if err != nil {
		return err
	}
	err = os.WriteFile(config.GetNetclientInstallPath(), binary, 0711)
	if err != nil {
		return err
	}

	if ncutils.FileExists(config.GetNetclientPath() + "winsw.xml") {
		logger.Log(0, "updating netclient service")
	}
	if err := writeServiceConfig(); err != nil {
		return err
	}

	if ncutils.FileExists(config.GetNetclientPath() + "winsw.exe") {
		logger.Log(0, "updating netclient binary")
	}
	err = ncutils.GetEmbedded()
	if err != nil {
		return err
	}
	logger.Log(0, "finished daemon setup")
	//get exact formatted commands
	runWinSWCMD("install")
	time.Sleep(time.Millisecond)
	runWinSWCMD("start")

	return nil
}

// start - starts window service
func start() error {
	return runWinSWCMD("start")
}

// stop - stops windows service
func stop() error {
	return runWinSWCMD("stop")
}

// restart - restarts windows service
func restart() error {
	runWinSWCMD("stop")
	time.Sleep(time.Millisecond)
	return runWinSWCMD("start")
}

// cleanup - cleans up windows files
func cleanUp() error {
	_ = writeServiceConfig() // will auto check if file is present before writing
	_ = runWinSWCMD("stop")
	_ = runWinSWCMD("uninstall")
	return os.RemoveAll(config.GetNetclientPath())
}

func writeServiceConfig() error {
	serviceConfigPath := config.GetNetclientPath() + "winsw.xml"
	scriptString := fmt.Sprintf(`<service>
<id>Netclient</id>
<name>Netclient</name>
<description>Manages Windows Netclient Hosts on one or more Netmaker networks.</description>
<executable>%v</executable>
<arguments>daemon</arguments>
<log mode="roll"></log>
<startmode>Automatic</startmode>
<delayedAutoStart>true</delayedAutoStart>
</service>
`, strings.Replace(config.GetNetclientPath()+"netclient.exe", `\\`, `\`, -1))
	if !ncutils.FileExists(serviceConfigPath) {
		err := os.WriteFile(serviceConfigPath, []byte(scriptString), 0600)
		if err != nil {
			return err
		}
		logger.Log(0, "wrote the daemon config file to the Netclient directory")
	}
	return nil
}

// runWinSWCMD - Run a command with the winsw.exe tool (start, stop, install, uninstall)
func runWinSWCMD(command string) error {

	// check if command allowed
	allowedCommands := map[string]bool{
		"start":     true,
		"stop":      true,
		"install":   true,
		"uninstall": true,
	}
	if !allowedCommands[command] {
		logger.Log(0, "command "+command+" unsupported by winsw")
		return errors.New("command not supported by winsw")
	}

	// format command
	dirPath := strings.Replace(config.GetNetclientPath(), `\\`, `\`, -1)
	winCmd := fmt.Sprintf(`"%swinsw.exe" "%s"`, dirPath, command)
	logger.Log(0, "running "+command+" of Windows Netclient daemon")

	// run command and log for success/failure
	out, err := ncutils.RunCmdFormatted(winCmd, true)
	if err != nil {
		logger.Log(0, "error with "+command+" of Windows Netclient daemon: "+err.Error()+" : "+out)
	} else {
		logger.Log(0, "successfully ran "+command+" of Windows Netclient daemon")
	}
	return err
}
