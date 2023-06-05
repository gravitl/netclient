package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SwitchServer - switches netclient server context
func SwitchServer(server string) error {
	fmt.Println("setting server context to " + server)
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
	_ = config.WriteNetclientConfig()
	return daemon.Restart()
}
