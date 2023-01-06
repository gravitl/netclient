//go:build !freebsd
// +build !freebsd

package functions

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	proxyCfg "github.com/gravitl/netclient/nmproxy/config"
	proxy_models "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// GetLocalListenPort - Gets the port running on the local interface
func GetLocalListenPort(ifacename string) (int, error) {
	client, err := wgctrl.New()
	if err != nil {
		logger.Log(0, "failed to start wgctrl")
		return 0, err
	}
	defer client.Close()
	device, err := client.Device(ifacename)
	if err != nil {
		logger.Log(0, "failed to parse interface", ifacename)
		return 0, err
	}
	return device.ListenPort, nil
}

// UpdateLocalListenPort - check local port, if different, mod config and publish
func UpdateLocalListenPort(node *config.Node) error {
	var err error
	ifacename := getRealIface(ncutils.GetInterfaceName(), node.Address)
	var proxylistenPort int
	if config.Netclient().ProxyEnabled {
		proxylistenPort = proxyCfg.GetCfg().HostInfo.PubPort
		if proxylistenPort == 0 {
			proxylistenPort = proxy_models.NmProxyPort
		}
	}
	localPort, err := GetLocalListenPort(ifacename)
	if err != nil {
		logger.Log(1, "network:", node.Network, "error encountered checking local listen port: ", ifacename, err.Error())
	} else if config.Netclient().LocalListenPort != localPort && localPort != 0 {
		logger.Log(1, "network:", node.Network, "local port has changed from ", strconv.Itoa(config.Netclient().LocalListenPort), " to ", strconv.Itoa(localPort))
		config.Netclient().LocalListenPort = localPort
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		if err := PublishNodeUpdate(node); err != nil {
			logger.Log(0, "could not publish local port change", err.Error())
		}
	} else if config.Netclient().ProxyEnabled && config.Netclient().ProxyListenPort != proxylistenPort {
		logger.Log(1, fmt.Sprint("network:", node.Network, "proxy listen port has changed from ", config.Netclient().ProxyListenPort, " to ", proxylistenPort))
		config.Netclient().ProxyListenPort = proxylistenPort
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		if err := PublishNodeUpdate(node); err != nil {
			logger.Log(0, "could not publish local port change", err.Error())
		}

	}
	return err
}

func getRealIface(ifacename string, address net.IPNet) string {
	var deviceiface = ifacename
	var err error
	if ncutils.IsMac() { // if node is Mac (Darwin) get the tunnel name first
		deviceiface, err = local.GetMacIface(address.IP.String())
		if err != nil || deviceiface == "" {
			deviceiface = ifacename
		}
	}
	return deviceiface
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
