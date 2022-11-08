//go:build freebsd
// +build freebsd

package functions

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

// GetLocalListenPort - Gets the port running on the local interface
func GetLocalListenPort(ifacename string) (int, error) {
	portstring, err := ncutils.RunCmd("wg show "+ifacename+" listen-port", false)
	if err != nil {
		return 0, err
	}
	portstring = strings.TrimSuffix(portstring, "\n")
	i, err := strconv.ParseInt(portstring, 10, 64)
	if err != nil {
		return 0, err
	} else if i == 0 {
		return 0, errors.New("parsed port is unset or invalid")
	}
	return int(i), nil
}

// UpdateLocalListenPort - check local port, if different, mod config and publish
func UpdateLocalListenPort(node *config.Node) error {
	var err error
	localPort, err := GetLocalListenPort(node.Interface)
	if err != nil {
		logger.Log(1, "network:", node.Network, "error encountered checking local listen port for interface : ", node.Interface, err.Error())
	} else if node.LocalListenPort != localPort && localPort != 0 {
		logger.Log(1, "network:", node.Network, "local port has changed from ", strconv.Itoa(node.LocalListenPort), " to ", strconv.Itoa(localPort))
		node.LocalListenPort = localPort
		err = config.WriteNodeConfig()
		if err != nil {
			return err
		}
		if err := PublishNodeUpdate(node); err != nil {
			logger.Log(0, "network:", node.Network, "could not publish local port change", err.Error())
		}
	}
	return err
}
