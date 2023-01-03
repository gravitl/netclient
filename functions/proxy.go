package functions

import "github.com/gravitl/netclient/config"

func Proxy(status bool) {
	config.Netclient().ProxyEnabled = status
	config.WriteNetclientConfig()
	// update host
	token, err := AuthenticateHost(config.Netclient())
	if err != nil {
		return nil, err
	}
}
