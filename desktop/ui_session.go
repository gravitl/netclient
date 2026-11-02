package desktop

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/scope"
	"golang.org/x/exp/slog"
)

var (
	registerDeviceOnServerForSession = RegisterDeviceOnServer
	leaveHostOnTenantForSession      = leaveHostOnTenant
	pullForSession                   = functions.Pull
)

// IsRegisteredToServer reports whether netclient is fully registered to the given server.
// A partial servers.json entry (API only, no TenantID) from configureServer does not count.
func IsRegisteredToServer(server string) bool {
	return config.IsRegisteredToServer(server)
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

	// Pull runs before uiapi.setSession stores the JWT. Expose the request
	// token so user-owned Authenticate does not fail closed mid-login.
	auth.SetPendingUserToken(authToken)
	defer auth.SetPendingUserToken("")

	if config.CurrServer != server {
		if err := config.SetCurrServerCtxInFile(server); err != nil {
			return err
		}
		config.CurrServer = server
		config.MarkServerContextChanged()
	}

	// Host JWT is process-global and keyed only by expiry — never reuse a token
	// minted against a previous CurrServer after a GUI server switch.
	auth.CleanJwtToken()

	alreadyRegistered := IsRegisteredToServer(server)
	tenantMatches := sessionTenantMatches(server, tenantID)
	prevTenant := previousEnrollmentTenant(server)
	// The host on this machine is owned by whoever registered it. A different
	// user must re-register so the server rebinds the device; otherwise join
	// fails with "host does not belong to user".
	owner := ""
	if host := config.Netclient(); host != nil {
		owner = strings.TrimSpace(host.OwnerUsername)
	}
	ownerMatches := owner == "" || owner == username

	// MSP tenant switch: server rejects the same host UUID under a new tenant
	// ("host already registered to another tenant"). Leave the previous tenant
	// before re-registering. Capture prevTenant before applySessionTenant.
	if alreadyRegistered && !tenantMatches && prevTenant != "" && prevTenant != tenantID {
		slog.Info("session: leaving previous tenant before register",
			"server", server, "from", prevTenant, "to", tenantID)
		if err := leaveHostOnTenantForSession(server, prevTenant, authToken); err != nil {
			slog.Warn("session: leave previous tenant failed; continuing to register",
				"from", prevTenant, "error", err)
		}
		clearLocalEnrollmentAfterTenantLeave(server)
		alreadyRegistered = IsRegisteredToServer(server)
	}

	applySessionTenant(server, tenantID)

	needRegister := !alreadyRegistered || !tenantMatches || !ownerMatches
	if needRegister {
		if err := registerDeviceOnServerForSession(server, authToken); err != nil {
			// Host may still exist under the previous tenant if leave failed or
			// local enrollment tenant was stale. Retry leave+register once.
			if isHostRegisteredToAnotherTenant(err) && prevTenant != "" && prevTenant != tenantID {
				slog.Warn("session: register blocked by previous tenant; retrying leave",
					"from", prevTenant, "error", err)
				if leaveErr := leaveHostOnTenantForSession(server, prevTenant, authToken); leaveErr != nil {
					return fmt.Errorf("%w (also failed to leave previous tenant: %v)", err, leaveErr)
				}
				clearLocalEnrollmentAfterTenantLeave(server)
				applySessionTenant(server, tenantID)
				if err2 := registerDeviceOnServerForSession(server, authToken); err2 != nil {
					return err2
				}
			} else {
				return err
			}
		}
	}

	if IsRegisteredToServer(server) {
		if _, _, _, err := pullForSession(false, true, false); err != nil {
			// Local servers.json can outlive the host row (reinstall, admin
			// delete). Re-enroll once instead of failing login forever.
			if isMissingHostOnServer(err) && !needRegister {
				slog.Warn("session pull: host missing on server, re-registering", "server", server, "error", err)
				if regErr := registerDeviceOnServerForSession(server, authToken); regErr != nil {
					return regErr
				}
				if _, _, _, err := pullForSession(false, true, false); err != nil {
					return fmt.Errorf("failed to sync with server: %w", err)
				}
			} else {
				return fmt.Errorf("failed to sync with server: %w", err)
			}
		}
	}
	// After POST /server, MQTT may still be on the previous broker. First-time
	// register already defers an in-process reset; re-login to a known server
	// must do the same so the daemon picks up the new context (manual
	// `netclient pull` restarts and masks this).
	if config.ConsumeServerContextChanged() {
		functions.MarkRegistrationResetPending()
	}
	return nil
}

// isMissingHostOnServer reports host authenticate/pull failures where the
// server no longer has this device (common after reinstall with leftover config).
func isMissingHostOnServer(err error) bool {
	return auth.IsMissingHostError(err)
}

func applySessionTenant(server, tenantID string) {
	_ = server
	// Only stamp the host for device API headers. servers.json TenantID is the
	// enrollment signal (IsRegisteredToServer) and must wait for register/pull.
	host := config.Netclient()
	if host != nil && host.TenantID != tenantID {
		host.TenantID = tenantID
		config.UpdateNetclient(*host)
		_ = config.WriteNetclientConfig()
	}
}

func sessionTenantMatches(server, tenantID string) bool {
	hostTenant := config.Netclient().TenantID
	if hostTenant != tenantID {
		return false
	}
	if srv := config.GetServer(server); srv != nil {
		// Not enrolled yet (no server TenantID): host match is enough.
		if strings.TrimSpace(srv.TenantID) == "" {
			return true
		}
		return srv.TenantID == tenantID
	}
	return tenantID == ""
}

// previousEnrollmentTenant is the tenant this host is currently enrolled under
// (server config preferred, then local host stamp).
func previousEnrollmentTenant(server string) string {
	if srv := config.GetServer(server); srv != nil {
		if t := strings.TrimSpace(srv.TenantID); t != "" {
			return t
		}
	}
	if host := config.Netclient(); host != nil {
		return strings.TrimSpace(host.TenantID)
	}
	return ""
}

func isHostRegisteredToAnotherTenant(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "host already registered to another tenant")
}

// leaveHostOnTenant deletes this device from the given tenant on the server so
// RegisterDevice can enroll the same host UUID under a different MSP tenant.
func leaveHostOnTenant(server, tenantID, userToken string) error {
	tenantID = strings.TrimSpace(tenantID)
	userToken = strings.TrimSpace(userToken)
	if tenantID == "" {
		return nil
	}
	if userToken == "" {
		return errors.New("user token required to leave previous tenant")
	}
	srv := config.GetServer(server)
	if srv == nil {
		return fmt.Errorf("server not found: %s", server)
	}
	api := config.NormalizeServerAPI(srv.API)
	if api == "" {
		api = config.NormalizeServerAPI(srv.APIHost)
	}
	if api == "" {
		return fmt.Errorf("server API not configured: %s", server)
	}
	host := config.Netclient()
	if host == nil || host.ID == uuid.Nil {
		return nil
	}

	url := fmt.Sprintf("%s/api/hosts/%s?force=true", config.APIBaseURL(api), host.ID.String())
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	auth.ApplyAPIHeaders(headers, userToken, host)
	headers.Set(scope.HeaderTenantID, tenantID)

	_, err := ncutils.SendRequest(http.MethodDelete, url, headers, nil)
	if err == nil {
		return nil
	}
	// Already gone on that tenant — safe to continue registering elsewhere.
	if isMissingHostOnServer(err) {
		return nil
	}
	var notOk ncutils.ErrStatusNotOk
	if errors.As(err, &notOk) && (notOk.Status == http.StatusNotFound || notOk.Status == http.StatusBadRequest) {
		msg := strings.ToLower(notOk.Message)
		if msg == "" || strings.Contains(msg, "not found") || strings.Contains(msg, "no host") {
			return nil
		}
	}
	return err
}

// clearLocalEnrollmentAfterTenantLeave drops nodes/peers and demotes the
// server entry so the next register is treated as a fresh enrollment. Does not
// ForceLogout — caller is mid PUT /session with a pending user JWT.
func clearLocalEnrollmentAfterTenantLeave(server string) {
	config.DeleteServerHostPeerCfg()
	for k, node := range config.GetNodes() {
		if node.Server == server || config.ResolveServerKey(node.Server) == config.ResolveServerKey(server) {
			config.DeleteNode(k)
		}
	}
	if err := config.WriteNodeConfig(); err != nil {
		slog.Warn("failed to write node config after tenant leave", "error", err)
	}
	_ = wireguard.SetPeers(true)

	if kept := config.DemoteServerToPartial(server); kept != "" {
		config.CurrServer = kept
		_ = config.SetCurrServerCtxInFile(kept)
		if err := config.WriteServerConfig(); err != nil {
			slog.Warn("failed to write server config after tenant leave", "error", err)
		}
	}
	if host := config.Netclient(); host != nil && strings.TrimSpace(host.TenantID) != "" {
		host.TenantID = ""
		config.UpdateNetclient(*host)
		_ = config.WriteNetclientConfig()
	}
}

// ReleaseSession disconnects all networks and optionally clears server context.
// Currently connected networks (and exit selection) are saved so the next login
// can restore them. Local default routes are restored before disconnect so
// logout does not wait on a daemon restart for internet to return.
func ReleaseSession(clearServer bool) error {
	defer functions.LogElapsed("logout")()
	// Latch before any teardown so peer updates that land mid-logout cannot
	// revive Connected or re-select the exit we are about to clear.
	beginSessionRelease()
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
		autoExit := config.GetDesiredAutoExit(user, tenant)
		egressID := config.GetDesiredEgressID(user, tenant)
		exitNetwork := config.GetDesiredExitNetwork(user, tenant)
		if nc := config.Netclient(); nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0) {
			wantIGW = true
		}
		token := uiapi.SessionAuthToken()
		if wantIGW && egressID == "" && !autoExit && token != "" {
			func() {
				defer functions.LogElapsed("logout exit selection lookup")()
				for _, network := range networks {
					sel, err := GetDeviceSelectedExitNode(network, token)
					if err != nil || sel == nil || strings.TrimSpace(sel.EgressID) == "" {
						continue
					}
					egressID = sel.EgressID
					exitNetwork = network
					break
				}
			}()
		}
		if egressID != "" || autoExit {
			wantIGW = true
			if exitNetwork == "" {
				exitNetwork = networks[len(networks)-1]
			}
		}
		if err := config.SnapshotDesiredState(user, tenant, networks, wantIGW, autoExit, egressID, exitNetwork); err != nil {
			slog.Warn("failed to persist connected networks before logout", "error", err)
		}
		skipNextDesiredRestore()

		// Bring LAN + OS DNS back immediately; do not wait for disconnect + daemon restart.
		functions.RestoreInternetGwAndDNS()
		// Clear server exit when we persisted exit intent (fixed or auto) to put back later.
		// Otherwise leave server selection intact so restore can still recover it.
		if (egressID != "" || autoExit) && exitNetwork != "" && token != "" {
			done := functions.LogElapsed("logout server exit clear")
			// One attempt. The shared client would otherwise retry a blackholed
			// API for about a minute after local routes are already restored.
			_, err := putDeviceExitNodeTimeout(exitNetwork, token, "", false, 5*time.Second)
			done()
			if err != nil {
				slog.Warn("failed to clear server exit node on logout", "network", exitNetwork, "error", err)
			}
		}

		var disconnectErr error
		for _, network := range networks {
			// Skip daemon restart per network — iface cleanup below is enough and
			// avoids the long SIGHUP path that made logout with exit feel stuck.
			if err := functions.DisconnectWithoutRestart(network, false); err != nil {
				// Do not return: one failed network must not skip the peer flush
				// below, which is what actually takes the tunnel down.
				slog.Warn("failed to disconnect network on logout", "network", network, "error", err)
				if disconnectErr == nil {
					disconnectErr = err
				}
			}
		}
		_ = wireguard.SetPeers(true)
		if disconnectErr != nil {
			clearDNSOnLogout()
			return disconnectErr
		}
	}
	clearDNSOnLogout()
	if clearServer {
		config.CurrServer = ""
		_ = config.SetCurrServerCtxInFile("")
	}
	auth.CleanJwtToken()
	return nil
}

// clearDNSOnLogout removes Netmaker OS DNS (NRPT on Windows) and listeners.
//
// Logout disconnects with restart=false, so nothing else stops the listeners,
// and the async DNS apply may still be mid-Configure from the exit teardown.
// Stop clears synchronously; the trailing schedule runs after any in-flight
// apply and, with no node connected, only resets.
func clearDNSOnLogout() {
	dns.GetDNSServerInstance().Stop()
	dns.FlushCache()
	dns.ScheduleReconfigure()
}
