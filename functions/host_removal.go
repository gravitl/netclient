package functions

import (
	"strings"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
)

// callForceLogout clears a Desktop UI session when that hook is registered.
func callForceLogout() {
	if GUI.ForceLogout != nil {
		GUI.ForceLogout()
	}
}

func callIsSessionActive() bool {
	if GUI.IsSessionActive == nil {
		return false
	}
	return GUI.IsSessionActive()
}

func callEnsureSessionLoaded() {
	if GUI.EnsureSessionLoaded != nil {
		GUI.EnsureSessionLoaded()
	}
}

// DisposeServerEnrollment demotes or deletes a servers.json entry after the
// host is gone remotely (DELETE_HOST, missing-host auth, mismatched MQID).
//
// Headless (nil KeepServerDomainForRelogin): DeleteServer — full wipe.
// Desktop: DemoteServerToPartial so Settings/Login keep the domain+API.
func DisposeServerEnrollment(serverName string) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return
	}
	wasActive := config.CurrServer == serverName ||
		config.ResolveServerKey(config.CurrServer) == config.ResolveServerKey(serverName)

	if GUI.KeepServerDomainForRelogin != nil && GUI.KeepServerDomainForRelogin() {
		if kept := config.DemoteServerToPartial(serverName); kept != "" {
			if wasActive {
				config.CurrServer = kept
				_ = config.SetCurrServerCtxInFile(kept)
			}
			if err := config.WriteServerConfig(); err != nil {
				slog.Warn("failed to write server config after demote", "error", err)
			}
			slog.Info("host removed: kept server domain for re-login", "server", kept)
			return
		}
	}

	config.DeleteServer(serverName)
	if err := config.WriteServerConfig(); err != nil {
		slog.Warn("failed to write server config after delete", "error", err)
	}
	if wasActive {
		config.SwitchToRemainingServer()
	}
}
