package functions

import (
	"fmt"
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

var (
	registerDeviceOnServerForSession = RegisterDeviceOnServer
	pullForSession                   = Pull
)

// IsRegisteredToServer reports whether netclient is fully registered to the given server.
// A partial servers.json entry (API set, Server empty) from configureServer does not count.
func IsRegisteredToServer(server string) bool {
	srv := config.GetServer(server)
	return srv != nil && strings.TrimSpace(srv.Server) != ""
}

// RegisterSession registers or refreshes a desktop UI session against a server.
// password is ignored (legacy desktop clients may still send it); authToken must be the user JWT.
// tenantID may be empty for classic non-MSP on-prem; MSP/SaaS should pass the workspace tenant.
func RegisterSession(server, username, authToken, password, tenantID string) error {
	_ = password
	server = config.NormalizeServerHost(server)
	tenantID = strings.TrimSpace(tenantID)
	if server == "" {
		return fmt.Errorf("server not configured")
	}
	if username == "" || authToken == "" {
		return fmt.Errorf("username and auth token are required")
	}
	if key := config.ResolveServerKey(server); key != "" {
		server = key
	}

	if config.CurrServer != server {
		if err := config.SetCurrServerCtxInFile(server); err != nil {
			return err
		}
		config.CurrServer = server
	}

	alreadyRegistered := IsRegisteredToServer(server)
	tenantMatches := sessionTenantMatches(server, tenantID)
	applySessionTenant(server, tenantID)

	if !alreadyRegistered || !tenantMatches {
		if err := registerDeviceOnServerForSession(server, authToken); err != nil {
			return err
		}
	}

	if IsRegisteredToServer(server) {
		if _, _, _, err := pullForSession(false, true, false); err != nil {
			return fmt.Errorf("failed to sync with server: %w", err)
		}
	}
	return nil
}

func applySessionTenant(server, tenantID string) {
	host := config.Netclient()
	if host != nil && host.TenantID != tenantID {
		host.TenantID = tenantID
		config.UpdateNetclient(*host)
		_ = config.WriteNetclientConfig()
	}
	if srv := config.GetServer(server); srv != nil && srv.TenantID != tenantID {
		srv.TenantID = tenantID
		_ = config.SaveServer(server, *srv)
	}
}

func sessionTenantMatches(server, tenantID string) bool {
	hostTenant := config.Netclient().TenantID
	if hostTenant != tenantID {
		return false
	}
	if srv := config.GetServer(server); srv != nil {
		// Empty stored tenant matches empty session tenant (classic on-prem).
		return srv.TenantID == tenantID
	}
	return tenantID == ""
}

// ReleaseSession disconnects all networks and optionally clears server context.
// Currently connected networks (and exit selection) are saved so the next login
// can restore them. Local default routes are restored before disconnect so
// logout does not wait on a daemon restart for internet to return.
func ReleaseSession(clearServer bool) error {
	networks := make([]string, 0, len(config.GetNodes()))
	for network, node := range config.GetNodes() {
		if node.Connected {
			networks = append(networks, network)
		}
	}
	if len(networks) > 0 {
		user, tenant := uiapi.SessionIdentity()
		// Prefer the persisted want_igw flag: CurrGwNmIP may already be cleared
		// (IGW monitor unhealthy / prior RestoreInternetGw) while exit is still desired.
		wantIGW := config.GetDesiredWantIGW(user, tenant)
		egressID := config.GetDesiredEgressID(user, tenant)
		exitNetwork := config.GetDesiredExitNetwork(user, tenant)
		if nc := config.Netclient(); nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0) {
			wantIGW = true
		}
		token := uiapi.SessionAuthToken()
		if wantIGW && egressID == "" && token != "" {
			for _, network := range networks {
				sel, err := GetDeviceSelectedExitNode(network, token)
				if err != nil || sel == nil || strings.TrimSpace(sel.EgressID) == "" {
					continue
				}
				egressID = sel.EgressID
				exitNetwork = network
				break
			}
		}
		if egressID != "" {
			wantIGW = true
			if exitNetwork == "" {
				exitNetwork = networks[len(networks)-1]
			}
		}
		if err := config.SnapshotDesiredState(user, tenant, networks, wantIGW, egressID, exitNetwork); err != nil {
			slog.Warn("failed to persist connected networks before logout", "error", err)
		}
		skipNextDesiredRestore()

		// Bring LAN back immediately; do not wait for disconnect + daemon restart.
		if nc := config.Netclient(); nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0) {
			if err := wireguard.RestoreInternetGw(); err != nil {
				slog.Warn("failed to restore default gateway before logout disconnect", "error", err)
			} else {
				reconfigureDNSAfterRouting()
			}
		}
		// Clear server exit only when we persisted an egress id to put back later.
		// Otherwise leave server selection intact so restore can still recover it.
		if egressID != "" && exitNetwork != "" && token != "" {
			if _, err := putDeviceExitNode(exitNetwork, token, ""); err != nil {
				slog.Warn("failed to clear server exit node on logout", "network", exitNetwork, "error", err)
			}
		}

		for _, network := range networks {
			// Skip daemon restart per network — iface cleanup below is enough and
			// avoids the long SIGHUP path that made logout with exit feel stuck.
			if err := disconnectNetwork(network, false, false); err != nil {
				return err
			}
		}
		_ = wireguard.SetPeers(true)
	}
	if clearServer {
		config.CurrServer = ""
		_ = config.SetCurrServerCtxInFile("")
	}
	auth.CleanJwtToken()
	return nil
}
