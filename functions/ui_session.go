package functions

import (
	"fmt"
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
)

var (
	registerDeviceOnServerForSession = RegisterDeviceOnServer
	pullForDesktopForSession         = PullForDesktop
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
		if _, _, _, err := pullForDesktopForSession(false, true); err != nil {
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
func ReleaseSession(clearServer bool) error {
	networks := make([]string, 0, len(config.GetNodes()))
	for network, node := range config.GetNodes() {
		if node.Connected {
			networks = append(networks, network)
		}
	}
	for _, network := range networks {
		if err := Disconnect(network); err != nil {
			return err
		}
	}
	if clearServer {
		config.CurrServer = ""
		_ = config.SetCurrServerCtxInFile("")
	}
	auth.CleanJwtToken()
	return nil
}
