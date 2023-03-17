package common

import (
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/go-ping/ping"
	"github.com/gravitl/netmaker/logger"
)

// *** Added here to avoid cyclic pkg import dependency with netclient ***
const (
	// LinuxAppDataPath - linux path
	LinuxAppDataPath = "/etc/netclient/"
	// MacAppDataPath - mac path
	MacAppDataPath = "/Applications/Netclient/"
	// WindowsAppDataPath - windows path
	WindowsAppDataPath = "C:\\Program Files (x86)\\Netclient\\"
)

// RunCmd - runs a local command
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		logger.Log(1, "error running command: ", command)
		logger.Log(1, strings.TrimSuffix(string(out), "\n"))
	}
	return string(out), err
}

// GetDataPath - returns path to netclient config directory
func GetDataPath() string {
	if runtime.GOOS == "windows" {
		return WindowsAppDataPath
	} else if runtime.GOOS == "darwin" {
		return MacAppDataPath
	} else {
		return LinuxAppDataPath
	}
}

func GetLatencyForPeerViaPinger(address string) uint64 {
	var latency uint64
	pinger, err := ping.NewPinger(address)
	if err != nil {
		logger.Log(0, "could not initiliaze ping peer address", address, err.Error())

	} else {
		pinger.Timeout = time.Second * 3
		err = pinger.Run()
		if err != nil {
			logger.Log(0, "failed to ping on peer address", address, err.Error())

		} else {
			pingStats := pinger.Statistics()
			if pingStats.PacketsRecv > 0 {
				latency = uint64(pingStats.AvgRtt.Milliseconds())
			}
		}
	}
	return latency
}
