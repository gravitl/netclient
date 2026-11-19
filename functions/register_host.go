package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/schema"
)

func PrepareRegistrationHost() (schema.Host, error) {
	return prepareRegistrationHost()
}

func prepareRegistrationHost() (schema.Host, error) {
	host := config.Netclient()
	ip, err := ncutils.GetInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else if ip != nil {
		host.Interfaces = ip
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else {
		host.DefaultInterface = defaultInterface
	}
	shouldUpdateHost, err := doubleCheck(host)
	if err != nil {
		return schema.Host{}, err
	}
	if shouldUpdateHost {
		host = config.Netclient()
	}
	return host.Host, nil
}
