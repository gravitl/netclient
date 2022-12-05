package common

import (
	"log"
	"os/exec"
	"runtime"
	"strings"
)

const (
	// LinuxAppDataPath - linux path
	LinuxAppDataPath = "/etc/netclient/"
	// MacAppDataPath - mac path
	MacAppDataPath = "/Applications/Netclient/"
	// WindowsAppDataPath - windows path
	WindowsAppDataPath = "C:\\Program Files (x86)\\Netclient\\"
)

// var IsHostNetwork bool
// var IsRelay bool
// var IsIngressGateway bool
// var IsRelayed bool
// var IsServer bool
// var InterfaceName string
// var BehindNAT bool

// var WgIfaceMap = models.WgIfaceConf{
// 	Iface:          nil,
// 	NetworkPeerMap: make(map[string]models.PeerConnMap), //done
// }

// var PeerKeyHashMap = make(map[string]models.RemotePeer) //done

// //var WgIfaceKeyMap = make(map[string]models.RemotePeer)

// var RelayPeerMap = make(map[string]map[string]models.RemotePeer)

// var ExtClientsWaitTh = make(map[string]models.ExtClientPeer)

// var ExtSourceIpMap = make(map[string]models.RemotePeer)

// RunCmd - runs a local command
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		log.Println("error running command: ", command)
		log.Println(strings.TrimSuffix(string(out), "\n"))
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
