package functions

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/scope"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SwitchServer - switches netclient server context to the given server, using
// the server's last-registered tenant.
func SwitchServer(server string) error {
	fmt.Println("setting netclient server context to " + server)
	srvCfg := config.GetServer(server)
	if srvCfg == nil {
		return errors.New("server config not found")
	}
	tenantID := srvCfg.TenantID
	hostID, ok := srvCfg.HostIDs[tenantID]
	if !ok {
		return fmt.Errorf("no host identity found for tenant %q on server %q", tenantID, server)
	}

	currServerCtx, _ := config.GetCurrServerCtxFromFile()
	netclient := config.Netclient()
	if server == currServerCtx && netclient.TenantID == tenantID {
		fmt.Println("netclient already switched to " + server + " context")
		return nil
	}

	if err := config.SetCurrServerCtxInFile(server); err != nil {
		fmt.Println("failed to set server context ", err)
		return err
	}
	netclient.ID = hostID
	netclient.TenantID = tenantID
	netclient.HostPeers = []wgtypes.PeerConfig{}
	_ = config.WriteNetclientConfig()
	return daemon.Restart()
}

// ListServers - lists all registered servers
func ListServers() error {
	fmt.Print("registered servers:\n\n")
	currServerCtx, err := config.GetCurrServerCtxFromFile()
	if err != nil {
		return err
	}
	for k := range config.Servers {
		if currServerCtx == k {
			fmt.Print("active: ")
		} else {
			fmt.Print("        ")
		}
		fmt.Println(k)
	}
	return nil
}

// LeaveServer - leave the named server. If tenantID is empty, every tenant
// registered on that server is left; otherwise only the given tenant is left.
func LeaveServer(s, tenantID string) error {
	server := config.GetServer(s)
	if server == nil {
		return errors.New("server not found")
	}

	var tenantsToLeave []string
	if tenantID != "" {
		if _, ok := server.HostIDs[tenantID]; !ok {
			return fmt.Errorf("tenant %q not found on server %q", tenantID, s)
		}
		tenantsToLeave = []string{tenantID}
	} else {
		for tid := range server.HostIDs {
			tenantsToLeave = append(tenantsToLeave, tid)
		}
	}

	currServerCtx, _ := config.GetCurrServerCtxFromFile()
	activeTenantLeaving := s == currServerCtx && slices.Contains(tenantsToLeave, config.Netclient().TenantID)

	for _, tid := range tenantsToLeave {
		if err := leaveServerTenant(server, tid); err != nil {
			return err
		}
		delete(server.HostIDs, tid)
	}

	serverRemoved := len(server.HostIDs) == 0
	if serverRemoved {
		config.DeleteServerHostPeerCfg()
		config.DeleteServer(server.Name)
		config.DeleteNodes()
		config.DeleteClientNodes()
	} else {
		config.UpdateServer(server.Name, *server)
	}

	if activeTenantLeaving {
		switchToRemainingServer(server, serverRemoved)
	}

	config.WriteServerConfig()
	config.WriteNodeConfig()
	config.WriteNetclientConfig()
	daemon.Restart()
	return nil
}

func switchToRemainingServer(leftServer *config.Server, serverRemoved bool) {
	netclient := config.Netclient()

	if !serverRemoved {
		for tenantID, hostID := range leftServer.HostIDs {
			netclient.ID = hostID
			netclient.TenantID = tenantID
			netclient.HostPeers = []wgtypes.PeerConfig{}
			return
		}
	}

	for _, name := range config.GetServers() {
		srvCfg := config.GetServer(name)
		if srvCfg == nil || len(srvCfg.HostIDs) == 0 {
			continue
		}
		tenantID := srvCfg.TenantID
		hostID, ok := srvCfg.HostIDs[tenantID]
		if !ok {
			for tid, hid := range srvCfg.HostIDs {
				tenantID, hostID, ok = tid, hid, true
				break
			}
		}
		_ = config.SetCurrServerCtxInFile(name)
		netclient.ID = hostID
		netclient.TenantID = tenantID
		netclient.HostPeers = []wgtypes.PeerConfig{}
		fmt.Println("switched netclient server context to " + name)
		return
	}

	// no servers left to switch to; clear the stale context
	_ = config.SetCurrServerCtxInFile("")
}

// leaveServerTenant deletes the host record for a single tenant on the given
// server. Auth failures are treated as non-fatal, matching prior behavior
// where local cleanup proceeds regardless.
func leaveServerTenant(server *config.Server, tenantID string) error {
	hostID, ok := server.HostIDs[tenantID]
	if !ok {
		return nil
	}
	tenantServer := *server
	tenantServer.TenantID = tenantID
	tenantHost := *config.Netclient()
	tenantHost.ID = hostID
	tenantHost.TenantID = tenantID
	auth.CleanJwtToken()
	token, err := auth.Authenticate(&tenantServer, &tenantHost)
	if err != nil {
		return nil
	}
	url := fmt.Sprintf("https://%s/api/hosts/%s?force=true", server.API, hostID.String())
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Authorization", "Bearer "+token)
	headers.Set(scope.HeaderTenantID, tenantID)
	_, err = ncutils.SendRequest(http.MethodDelete, url, headers, nil)
	return err
}
