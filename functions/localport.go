package functions

import (
	"github.com/gravitl/netmaker/logger"
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
