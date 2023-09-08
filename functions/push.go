package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/models"
)

// Push - updates server with new host config
func Push() error {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server cfg is nil")
	}
	if err := setupMQTTSingleton(server, true); err != nil {
		return err
	}
	if err := PublishHostUpdate(server.Server, models.UpdateHost); err != nil {
		return err
	}
	if err := config.WriteNetclientConfig(); err != nil {
		return err
	}
	if err := daemon.Restart(); err != nil {
		if err := daemon.Start(); err != nil {
			return fmt.Errorf("daemon restart failed %w", err)
		}
	}
	return nil
}
