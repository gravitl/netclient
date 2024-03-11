package ncutils

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/gravitl/netmaker/logger"
)

//go:embed windowsdaemon/winsw.exe
var winswContent embed.FS

const WIN_PATH = "C:\\Program Files (x86)\\Netclient\\"

// RunCmd - runs a local command
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Wait()
	//cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/C \"" + command + "\""}
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		logger.Log(0, "error running command:", command)
		logger.Log(0, strings.TrimSuffix(string(out), "\n"))
	}
	return string(out), err
}

// RunCmd - runs a local command
func RunCmdFormatted(command string, printerr bool) (string, error) {
	var comSpec = os.Getenv("COMSPEC")
	if comSpec == "" {
		comSpec = os.Getenv("SystemRoot") + "\\System32\\cmd.exe"
	}
	cmd := exec.Command(comSpec)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/C \"" + command + "\""}
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		logger.Log(0, "error running command:", command)
		logger.Log(0, strings.TrimSuffix(string(out), "\n"))
	}
	return string(out), err
}

// StartCmdFormatted - runs a local command, without wait for response
func StartCmdFormatted(command string) error {
	var comSpec = os.Getenv("COMSPEC")
	if comSpec == "" {
		comSpec = os.Getenv("SystemRoot") + "\\System32\\cmd.exe"
	}
	cmd := exec.Command(comSpec)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/C \"" + command + "\""}
	cmd.Start()

	return nil
}

// GetEmbedded - Gets the Windows daemon creator
func GetEmbedded() error {
	data, err := winswContent.ReadFile("windowsdaemon/winsw.exe")
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("%swinsw.exe", WIN_PATH)
	err = os.WriteFile(fileName, data, 0700)
	if err != nil {
		logger.Log(0, "could not mount winsw.exe")
		return err
	}
	return nil
}

// IsBridgeNetwork - check if the interface is a bridge type
func IsBridgeNetwork(ifaceName string) bool {
	return false
}
