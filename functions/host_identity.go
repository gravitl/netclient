package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/posture"
	"github.com/gravitl/netmaker/schema"
)

// UpdateHostFromServer merges a server host payload into local config. Posture
// identity fields are never taken from the server; they are restored from local
// config and then refreshed from the machine.
func UpdateHostFromServer(host *schema.Host) (resetInterface, restart, sendHostUpdate bool) {
	resetInterface, restart, sendHostUpdate = config.UpdateHost(host)
	refreshHostIdentityInConfig()
	return resetInterface, restart, sendHostUpdate
}

func refreshHostIdentityInConfig() {
	hostCfg := config.Netclient()
	if hostCfg == nil {
		return
	}
	updated := *hostCfg
	if !posture.ApplyIdentityIfChanged(&updated.Host) {
		return
	}
	config.UpdateNetclient(updated)
	_ = config.WriteNetclientConfig()
}
