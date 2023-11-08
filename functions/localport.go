package functions

import (
	"net"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/stun"
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

func getInterfaces() (*[]models.Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var data = []models.Iface{}
	var link models.Iface
	for _, iface := range ifaces {
		iface := iface
		if iface.Flags&net.FlagUp == 0 || // interface down
			iface.Flags&net.FlagLoopback != 0 || // loopback interface
			iface.Flags&net.FlagPointToPoint != 0 || // avoid direct connections
			iface.Name == ncutils.GetInterfaceName() || strings.Contains(iface.Name, "netmaker") || // avoid netmaker
			ncutils.IsBridgeNetwork(iface.Name) || // avoid bridges
			strings.Contains(iface.Name, "docker") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, cidr, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLoopback() || // no need to send loopbacks
				stun.IsPublicIP(ip) { // no need to send public IPs
				continue
			}
			link.Name = iface.Name
			link.Address = *cidr
			link.Address.IP = ip
			data = append(data, link)
		}
	}
	return &data, nil
}
