//go:build freebsd
// +build freebsd

package functions

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// GetLocalListenPort - Gets the port running on the local interface
func GetLocalListenPort(ifacename string) (int32, error) {
	portstring, err := ncutils.RunCmd("wg show "+ifacename+" listen-port", false)
	if err != nil {
		return 0, err
	}
	portstring = strings.TrimSuffix(portstring, "\n")
	i, err := strconv.ParseInt(portstring, 10, 32)
	if err != nil {
		return 0, err
	} else if i == 0 {
		return 0, errors.New("parsed port is unset or invalid")
	}
	return int32(i), nil
}

// UpdateLocalListenPort - check local port, if different, mod config and publish
func UpdateLocalListenPort(node *config.Node) error {
	var err error
	localPort, err := GetLocalListenPort("netmaker")
	if err != nil {
		logger.Log(1, "network:", node.Network, "error encountered checking local listen port for interface netmaker", err.Error())
	} else if config.Netclient().LocalListenPort != int(localPort) && localPort != 0 {
		logger.Log(1, "network:", node.Network, "local port has changed from ", strconv.Itoa(int(config.Netclient().LocalListenPort)), " to ", strconv.Itoa(int(localPort)))
		config.Netclient().LocalListenPort = int(localPort)
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		if err := PublishNodeUpdate(node); err != nil {
			logger.Log(0, "could not publish local port change", err.Error())
		}
	}
	return err
}

func getInterfaces() (*[]models.Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var data []models.Iface
	var link models.Iface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			link.Name = iface.Name
			_, cidr, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			link.Address = *cidr
			data = append(data, link)
		}
	}
	return &data, nil
}
