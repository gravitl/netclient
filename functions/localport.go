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
func UpdateLocalListenPort() error {
	var err error
	publishMsg := false
	ifacename := ncutils.GetInterfaceName()
	var proxylistenPort int
	var proxypublicport int
	if config.Netclient().ProxyEnabled {
		proxylistenPort = proxyCfg.GetCfg().HostInfo.PrivPort
		proxypublicport = proxyCfg.GetCfg().HostInfo.PubPort
		if proxylistenPort == 0 {
			proxylistenPort = proxy_models.NmProxyPort
		}
		if proxypublicport == 0 {
			proxypublicport = proxy_models.NmProxyPort
		}
	}
	localPort, err := GetLocalListenPort(ifacename)
	if err != nil {
		logger.Log(1, "error encountered checking local listen port: ", ifacename, err.Error())
	} else if config.Netclient().ListenPort != localPort && localPort != 0 {
		logger.Log(1, "local port has changed from ", strconv.Itoa(config.Netclient().ListenPort), " to ", strconv.Itoa(localPort))
		config.Netclient().ListenPort = localPort
		publishMsg = true
	}
	if config.Netclient().ProxyEnabled {
		if config.Netclient().ProxyListenPort != proxylistenPort {
			logger.Log(1, fmt.Sprint("proxy listen port has changed from ", config.Netclient().ProxyListenPort, " to ", proxylistenPort))
			config.Netclient().ProxyListenPort = proxylistenPort
			publishMsg = true

		}
		if config.Netclient().PublicListenPort != proxypublicport {
			logger.Log(1, fmt.Sprint("public listen port has changed from ", config.Netclient().PublicListenPort, " to ", proxypublicport))
			config.Netclient().PublicListenPort = proxypublicport
			publishMsg = true
		}
	}
	if publishMsg {
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		logger.Log(0, "publishing global host update for port changes")
		if err := PublishGlobalHostUpdate(models.UpdateHost); err != nil {
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
