package functions

import (
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// ClearEnrollmentIfHostMissing clears local enrollment when authenticate/pull
// reports the host is gone on the server (400 record not found). Headless
// deletes the server entry; Desktop demotes it for re-login. Stops treating
// the host as enrolled so mqFallback stops spamming Pull.
func ClearEnrollmentIfHostMissing(serverName string, err error) bool {
	if !auth.IsMissingHostError(err) {
		return false
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		serverName = config.CurrServer
	}
	if serverName == "" {
		return false
	}
	// Already demoted / never fully enrolled — nothing more to do.
	if !IsServerFullyRegistered(serverName) {
		return true
	}

	logger.Log(0, "host missing on server; clearing enrollment for", serverName, ":", err.Error())
	auth.CleanJwtToken()
	callForceLogout()

	config.DeleteServerHostPeerCfg()
	for k, node := range config.GetNodes() {
		if node.Server == serverName {
			config.DeleteNode(k)
		}
	}
	if writeErr := config.WriteNodeConfig(); writeErr != nil {
		slog.Warn("failed to write node config after missing host", "error", writeErr)
	}
	_ = wireguard.SetPeers(true)

	DisposeServerEnrollment(serverName)
	return true
}

// IsServerFullyRegistered reports whether CurrServer (or name) still has a
// full enrollment (Server and/or TenantID present). Partial Settings entries
// do not count.
func IsServerFullyRegistered(name string) bool {
	if name == "" {
		name = config.CurrServer
	}
	return config.IsRegisteredToServer(name)
}
