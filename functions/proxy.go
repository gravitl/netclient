package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// ChangeProxyStatus - updates proxy status on host and publishes global host update
func ChangeProxyStatus(status bool) error {
	logger.Log(1, fmt.Sprint("changing proxy status to ", status))
	servers := config.GetServers()
	for _, server := range servers {
		serverCfg := config.GetServer(server)
		if serverCfg == nil {
			continue
		}
		err := setupMQTTSingleton(serverCfg, true)
		if err != nil {
			logger.Log(0, "failed to set up mq conn for server ", server)
		}
	}
	config.Netclient().ProxyEnabled = status
	if err := config.WriteNetclientConfig(); err != nil {
		return err
	}
	if err := PublishGlobalHostUpdate(models.UpdateHost); err != nil {
		return err
	}
	if status {
		fmt.Println("proxy is switched on")
	} else {
		fmt.Println("proxy is switched off")
	}
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "failed to restart daemon: ", err.Error())
	}
	return nil
}
