package functions

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SwitchServer - switches netclient server context
func SwitchServer(server string) error {
	fmt.Println("setting netclient server context to " + server)
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

// ListServers - lists all registered servers
func ListServers() error {
	fmt.Print("registered servers:\n\n")
	currServerCtx, err := config.GetCurrServerCtxFromFile()
	if err != nil {
		return err
	}
	for k := range config.Servers {
		if currServerCtx == k {
			fmt.Print("active: ")
		} else {
			fmt.Print("        ")
		}
		fmt.Println(k)
	}
	return nil
}

// LeaveServer - leave the named server
func LeaveServer(s string) error {
	server := config.GetServer(s)
	if server == nil {
		return errors.New("server not found")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		return err
	}
	id := config.Netclient().ID.String()
	endpoint := httpclient.Endpoint{
		URL:           "https://" + server.API,
		Route:         "/api/hosts/" + id + "?force=true",
		Method:        http.MethodDelete,
		Authorization: "Bearer " + token,
		Data:          "",
	}
	_, err = endpoint.GetResponse()
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			fmt.Println("error leaving server", s)
		}
		fmt.Println(err)
		return err
	}
	config.DeleteServer(server.Name)
	config.WriteServerConfig()
	daemon.Restart()
	return nil
}
