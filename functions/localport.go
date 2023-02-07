package functions

import (
	"net"

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
			ip, cidr, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			link.Address = *cidr
			link.Address.IP = ip
			data = append(data, link)
		}
	}
	return &data, nil
}
