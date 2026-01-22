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
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
)

var serviceConfigPath = config.GetNetclientPath() + "winsw.xml"

// install - sets up the Windows daemon service
func install() error {
	if err := writeServiceConfig(); err != nil {
		os.Exit(3)
		return err
	}
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

	err = ncutils.GetEmbedded()
	if err != nil {
		return err
	}
	// get exact formatted commands
	if err = runWinSWCMD("install"); err != nil {
		for i := 0; i < 3; i++ {
			fmt.Printf("Attempting to remove previously installed netclient service\n")
			_ = runWinSWCMD("uninstall")
			time.Sleep(time.Second >> 1)
			if err = runWinSWCMD("install"); err == nil {
				fmt.Printf("successfully installed netclient service")
				break
			}
		}
	}
	time.Sleep(time.Millisecond)
	logger.Log(0, "finished daemon setup")

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
	if err := runWinSWCMD("restart!"); err != nil {
		if strings.Contains(err.Error(), "Failed to stop the service") {
			return runWinSWCMD("start")
		}
		return err
	}
	return nil
}

// hardRestart - restarts windows service  - no special handling on Windows
func hardRestart() error {
	return restart()
}

// cleanup - cleans up windows files
func cleanUp() error {
	_ = writeServiceConfig() // will auto check if file is present before writing
	_ = runWinSWCMD("stop")
	_ = runWinSWCMD("uninstall")
	//delete the key for adapter in registry
	deleteRegistryKeys()
	time.Sleep(8 * time.Second)
	os.RemoveAll(config.GetNetclientPath())

	msg := "uninstalling...the window will be closed automatically"
	winCmd := fmt.Sprintf(`start "%s" /min timeout /t 2 /nobreak > null && rmdir /s /q "%s"`, msg, config.GetNetclientPath())

	return ncutils.StartCmdFormatted(winCmd)
}

// deleteRegistryKeys - delete the keys in registry for netmaker profiles
func deleteRegistryKeys() {
	//get key for Profiles
	key := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
	mainK, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		slog.Error("error opening key in registry", "error", key, err.Error())
		return
	}
	defer mainK.Close()

	//get all the subkey under Profiles
	subKeys, err := mainK.ReadSubKeyNames(-1)
	if err != nil {
		slog.Error("error reading sub keys", "error", err.Error())
		return
	}

	//iterate the sub keys and delete the one with Description:netmaker and ProfileName:netmaker X
	for _, k := range subKeys {

		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, key+`\`+k, registry.QUERY_VALUE)
		if err != nil {
			slog.Error("error opening key in registry", "error", key+`\`+k, err.Error())
			subKey.Close()
			continue
		}

		desc, _, err := subKey.GetStringValue("Description")
		if err != nil {
			slog.Error("error getting Description", "error", key+`\`+k, err.Error())
		}
		pName, _, err := subKey.GetStringValue("ProfileName")
		if err != nil {
			slog.Error("error getting Description", "error", key+`\`+k, err.Error())
		}

		//if Description and profile name are with prefix netmaker, delete the subkey
		if strings.HasPrefix(desc, "netmaker") && strings.HasPrefix(pName, "netmaker") {
			err = registry.DeleteKey(registry.LOCAL_MACHINE, key+`\`+k)
			if err != nil {
				slog.Error("error deleting key in registry", "error", key+`\`+k)
			}
		}
		subKey.Close()
	}
}

func writeServiceConfig() error {

	scriptString := fmt.Sprintf(`<service>
<id>netclient</id>
<name>netclient</name>
<description>Manages Windows Netclient Hosts on one or more Netmaker networks.</description>
<executable>%s</executable>
<arguments>daemon</arguments>
<env name="PATH" value="%%PATH%%;%%SystemRoot%%\System32;%%SystemRoot%%\Sysnative" />
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
	if !ncutils.FileExists(serviceConfigPath) {
		return nil
	}

	// check if command allowed
	allowedCommands := map[string]bool{
		"start":     true,
		"stop":      true,
		"install":   true,
		"uninstall": true,
		"restart!":  true,
	}
	if !allowedCommands[command] {
		logger.Log(0, "command "+command+" unsupported by winsw")
		return errors.New("command not supported by winsw")
	}

	// format command
	dirPath := strings.Replace(config.GetNetclientPath(), `\\`, `\`, -1)
	winCmd := fmt.Sprintf(`"%swinsw.exe" "%s"`, dirPath, command)
	logger.Log(1, "running "+command+" of Windows Netclient daemon")
	// run command and log for success/failure
	out, err := ncutils.RunCmdFormatted(winCmd, true)
	if err != nil {
		logger.Log(0, "error with "+command+" of Windows Netclient daemon: "+err.Error()+" : "+out)
	} else {
		logger.Log(1, "successfully ran "+command+" of Windows Netclient daemon")
	}
	return err
}

// GetInitType - returns the init type (not applicable for windows)
func GetInitType() config.InitType {
	return config.UnKnown
}
