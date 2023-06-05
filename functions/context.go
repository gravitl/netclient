package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SwitchServer - switch netclient server context
func SwitchServer(server string) error {
	fmt.Println("setting context to " + server)
	if config.GetServer(server) == nil {
		return errors.New("server config not found")
	}
	currServerCtx, err := config.GetCurrServerCtxFromFile()
	if err == nil {
		if server == currServerCtx {
			fmt.Println("netclient already switched to " + server + " context")
			return nil
		}
	}

	err = config.SetCurrServerCtxInFile(server)
	if err != nil {
		fmt.Println("failed to set server context ", err)
		return err
	}
	config.Netclient().HostPeers = []wgtypes.PeerConfig{}
	config.WriteNetclientConfig()
	return daemon.Restart()
}
