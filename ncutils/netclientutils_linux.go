package ncutils

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// RunCmd - runs a local command
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		logger.Log(0, fmt.Sprintf("error running command: %s", command))
		logger.Log(0, strings.TrimSuffix(string(out), "\n"))
	}
	return string(out), err
}

// RunCmdFormatted - does nothing for linux
func RunCmdFormatted(command string, printerr bool) (string, error) {
	return "", nil
}

// GetEmbedded - if files required for linux, put here
func GetEmbedded() error {
	return nil
}

// IsBridgeNetwork - check if the interface is a bridge type
func IsBridgeNetwork(ifaceName string) bool {

	l, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return false
	}
	if strings.ToLower(l.Type()) == "bridge" {
		slog.Debug(fmt.Sprintf("Interface is a bridge network: %+v", ifaceName))
		return true
	}
	if _, ok := l.(*netlink.Bridge); ok {
		slog.Debug(fmt.Sprintf("Interface is a bridge network: %+v", ifaceName))
		return true
	}
	return false
}
