package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	// Ensure the installation directory exists
	installPath := config.GetNetclientInstallPath()
	installDir := filepath.Dir(installPath)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(binarypath)
	if err != nil {
		return err
	}

	// Write to a temporary file first, then rename to avoid issues with locked files
	tmpPath := installPath + ".tmp"
	if err := os.WriteFile(tmpPath, binary, 0711); err != nil {
		return fmt.Errorf("failed to write binary to temporary file: %w", err)
	}

	// Remove the old file if it exists (might fail if locked, but that's okay)
	_ = os.Remove(installPath)

	// Rename the temporary file to the final location
	if err := os.Rename(tmpPath, installPath); err != nil {
		// Clean up temp file on error
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to install binary: %w", err)
	}

	err = ncutils.GetEmbedded()
	if err != nil {
		return err
	}
	// Always try to stop and uninstall existing service before installing
	// This prevents "service already exists" errors
	slog.Info("ensuring any existing service is stopped and uninstalled before installation")
	_ = runWinSWCMD("stop")
	time.Sleep(time.Second * 2)
	_ = runWinSWCMD("uninstall")
	time.Sleep(time.Second * 2)

	// Now install the service
	if err = runWinSWCMD("install"); err != nil {
		// If install still fails, try one more time with stop/uninstall
		slog.Warn("service install failed, retrying after stop/uninstall", "error", err)
		_ = runWinSWCMD("stop")
		time.Sleep(time.Second * 2)
		_ = runWinSWCMD("uninstall")
		time.Sleep(time.Second * 2)
		if err = runWinSWCMD("install"); err != nil {
			return fmt.Errorf("failed to install service: %w", err)
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
	var allErrors []string

	// Write service config if it doesn't exist (needed for uninstall)
	if ncutils.FileExists(serviceConfigPath) {
		_ = writeServiceConfig()
	} else {
		// If config doesn't exist, try to create it from the install path
		// This handles cases where the service exists but config was deleted
		installPath := config.GetNetclientInstallPath()
		if ncutils.FileExists(installPath) {
			_ = writeServiceConfig()
		}
	}

	// Stop the service first
	slog.Info("stopping netclient service")
	if err := runWinSWCMD("stop"); err != nil {
		slog.Warn("failed to stop service (may already be stopped)", "error", err)
		// Continue even if stop fails - service might not be running
	} else {
		// Wait for service to fully stop
		time.Sleep(time.Second * 3)
	}

	// Uninstall the service
	slog.Info("uninstalling netclient service")
	if err := runWinSWCMD("uninstall"); err != nil {
		slog.Warn("failed to uninstall service (may not be installed)", "error", err)
		// Continue even if uninstall fails - service might not exist
	} else {
		// Wait for service to be fully removed
		time.Sleep(time.Second * 2)
	}

	// Delete registry keys for network profiles
	slog.Info("cleaning up registry keys")
	deleteRegistryKeys()

	// Wait a bit more to ensure all file handles are released
	time.Sleep(time.Second * 2)

	// Remove the netclient directory and all files
	netclientPath := config.GetNetclientPath()
	slog.Info("removing netclient files", "path", netclientPath)

	// Try to remove files directly first
	if err := os.RemoveAll(netclientPath); err != nil {
		slog.Warn("failed to remove netclient directory directly", "error", err, "path", netclientPath)
		allErrors = append(allErrors, fmt.Sprintf("failed to remove directory: %v", err))

		// If direct removal fails, try using PowerShell to force delete
		// This handles locked files better than os.RemoveAll
		slog.Info("attempting PowerShell deletion for locked files")
		psCmd := fmt.Sprintf("Get-ChildItem -Path '%s' -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; if (Test-Path '%s') { $fso = New-Object -ComObject Scripting.FileSystemObject; $fso.DeleteFolder('%s', $true) }", netclientPath, netclientPath, netclientPath)
		winCmd := fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -Command "%s"`, psCmd)
		_, err2 := ncutils.RunCmdFormatted(winCmd, false)
		if err2 != nil {
			slog.Warn("PowerShell deletion also failed", "error", err2)
			allErrors = append(allErrors, fmt.Sprintf("PowerShell deletion failed: %v", err2))
		} else {
			slog.Info("PowerShell deletion completed")
		}
	} else {
		slog.Info("successfully removed netclient directory")
	}

	// Also try to remove the installed binary if it's in a different location
	installPath := config.GetNetclientInstallPath()
	if installPath != netclientPath+"netclient.exe" {
		if err := os.Remove(installPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove installed binary", "error", err, "path", installPath)
			allErrors = append(allErrors, fmt.Sprintf("failed to remove binary: %v", err))
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("uninstall completed with errors: %s", strings.Join(allErrors, "; "))
	}

	return nil
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

	// Configure log path to preserve logs across restarts
	// Note: GetNetclientPath() already returns paths with single backslashes
	// (the \\ in source code is just Go's escape sequence)
	executablePath := config.GetNetclientPath() + "netclient.exe"
	workingDir := config.GetNetclientPath()
	logPath := config.GetNetclientPath() + "logs"
	// WinSW creates log files based on the wrapper executable name (winsw.exe -> winsw.out.log, winsw.err.log)
	// Use mode="append" to preserve logs across service restarts
	// Logs will be created in the logpath: winsw.out.log (stdout) and winsw.err.log (stderr)
	scriptString := fmt.Sprintf(`<service>
<id>netclient</id>
<name>Netclient</name>
<description>Manages Windows Netclient on one or more Netmaker networks.</description>
<executable>%s</executable>
<arguments>daemon</arguments>
<workingdirectory>%s</workingdirectory>
<env name="PATH" value="%%PATH%%;%%SystemRoot%%\System32;%%SystemRoot%%\Sysnative" />
<logpath>%s</logpath>
<log mode="append" />
<startmode>Automatic</startmode>
<delayedAutoStart>true</delayedAutoStart>
<stoptimeout>30sec</stoptimeout>
<resetfailure>1 hour</resetfailure>
<onfailure action="restart" delay="5 sec"/>
<onfailure action="restart" delay="15 sec"/>
<onfailure action="restart" delay="30 sec"/>
<onfailure action="restart" delay="120 sec"/>
<onfailure action="restart" delay="300 sec"/>
</service>
`, executablePath, workingDir, logPath)
	// Always write/update the config to ensure log settings are correct
	fileExisted := ncutils.FileExists(serviceConfigPath)
	err := os.WriteFile(serviceConfigPath, []byte(scriptString), 0600)
	if err != nil {
		return err
	}
	if !fileExisted {
		slog.Debug("wrote the daemon config file to the Netclient directory")
	} else {
		slog.Debug("updated the daemon config file with log preservation settings")
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
	// Note: GetNetclientPath() already returns paths with single backslashes
	// WinSW automatically finds winsw.xml in the same directory as winsw.exe
	// Log files are named based on the wrapper executable: winsw.out.log and winsw.err.log
	dirPath := config.GetNetclientPath()
	winCmd := fmt.Sprintf(`"%swinsw.exe" %s`, dirPath, command)
	logger.Log(1, "running "+command+" of Windows Netclient daemon")
	// run command and log for success/failure
	out, err := ncutils.RunCmdFormatted(winCmd, false) // Don't print errors to console for suppressible cases
	if err != nil {
		// Suppress "service does not exist" errors for stop and uninstall commands
		// Exit status 1060 means "The specified service does not exist as an installed service"
		if (command == "stop" || command == "uninstall") &&
			(strings.Contains(err.Error(), "1060") ||
				strings.Contains(err.Error(), "does not exist") ||
				strings.Contains(out, "does not exist")) {
			logger.Log(1, "service does not exist (already stopped/uninstalled), continuing")
			return nil
		}
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
