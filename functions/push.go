package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/models"
)

// Push - updates server with new host config
func Push(restart bool) error {
	server := config.GetServer(config.CurrServer)
	if server != nil {
		if err := setupMQTTSingleton(server, true); err == nil {
			if err := PublishHostUpdate(server.Server, models.UpdateHost); err != nil {
				return err
			}
			Mqclient.Disconnect(250)
		} else {
			if err := hostServerUpdate(models.HostUpdate{Action: models.UpdateHost}); err != nil {
				return err
			}
		}

	}
	if err := config.WriteNetclientConfig(); err != nil {
		return err
	}
	if restart {
		if err := daemon.Restart(); err != nil {
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("daemon restart failed %w", err)
			}
		}
	}

	return nil
}
