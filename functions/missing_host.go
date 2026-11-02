package functions

import (
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// ClearEnrollmentIfHostMissing demotes local enrollment when authenticate/pull
// reports the host is gone on the server (400 record not found). Keeps the
// server domain for Desktop re-login, clears the UI session, and stops treating
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
	uiapi.ForceLogout()

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

	wasActive := config.CurrServer == serverName ||
		config.ResolveServerKey(config.CurrServer) == config.ResolveServerKey(serverName)
	if kept := config.DemoteServerToPartial(serverName); kept != "" {
		if wasActive {
			config.CurrServer = kept
			_ = config.SetCurrServerCtxInFile(kept)
		}
		if writeErr := config.WriteServerConfig(); writeErr != nil {
			slog.Warn("failed to write server config after missing host demote", "error", writeErr)
		}
		slog.Info("host missing: demoted server for re-login", "server", kept)
		return true
	}
	config.DeleteServer(serverName)
	if writeErr := config.WriteServerConfig(); writeErr != nil {
		slog.Warn("failed to write server config after missing host delete", "error", writeErr)
	}
	if wasActive {
		config.SwitchToRemainingServer()
	}
	return true
}

// IsServerFullyRegistered reports whether CurrServer (or name) still has a
// full enrollment (Server identity set). Partial Settings entries do not count.
func IsServerFullyRegistered(name string) bool {
	if name == "" {
		name = config.CurrServer
	}
	srv := config.GetServer(name)
	return srv != nil && strings.TrimSpace(srv.Server) != ""
}
