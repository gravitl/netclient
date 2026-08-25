package functions

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/internal/proxyuplink"
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
)

var exitNodeApplyMu sync.Mutex

// pullAndApplyExitNodeChange pulls host config and applies WireGuard/IGW routes
// in-process. CLI `netclient pull` restarts the daemon; desktop selection must
// apply the same routing without a restart.
func pullAndApplyExitNodeChange(network string, wantGW bool) {
	exitNodeApplyMu.Lock()
	defer exitNodeApplyMu.Unlock()
	prev4 := ipCopy(config.Netclient().CurrGwNmIP)
	prev6 := ipCopy(config.Netclient().CurrGwNmIP6)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * 400 * time.Millisecond)
		}
		resp, _, _, err := PullForDesktop(false, true)
		if err != nil {
			lastErr = err
			slog.Warn("failed to pull after exit node change",
				"network", network, "attempt", attempt, "error", err)
			continue
		}
		if !hostPullReflectsExitNodeChange(resp, wantGW, prev4, prev6) {
			lastErr = fmt.Errorf("host pull has not reflected exit-node change yet")
			slog.Info("host pull has not reflected exit node change yet",
				"network", network, "attempt", attempt, "change_default_gw", resp.ChangeDefaultGw)
			if attempt < 3 {
				continue
			}
			// Last attempt: still apply so a slightly stale pull can install routes.
		}
		if err := applyHostPullRouting(resp); err != nil {
			lastErr = err
			continue
		}
		return
	}
	if lastErr != nil {
		slog.Warn("exit node routing not applied after pull; MQTT peer update may still apply it",
			"network", network, "error", lastErr)
	}
}

func hostPullReflectsExitNodeChange(resp models.HostPull, wantGW bool, prev4, prev6 net.IP) bool {
	if !wantGW {
		return !resp.ChangeDefaultGw
	}
	if !resp.ChangeDefaultGw {
		return false
	}
	gw4, gw6 := wireguard.NormalizeIGWNexthops(resp.DefaultGwIp, resp.DefaultGwIp6)
	if gw4 == nil && gw6 == nil {
		return false
	}
	if len(prev4) == 0 && len(prev6) == 0 {
		return true
	}
	same4 := ipEqual(prev4, gw4)
	same6 := ipEqual(prev6, gw6)
	// Switching A→B: unchanged nexthop means the pull is still stale.
	return !same4 || !same6
}

func applyHostPullRouting(pull models.HostPull) error {
	config.UpdateHostPeers(pull.Peers)
	if err := wireguard.SetPeers(true); err != nil {
		slog.Error("failed to apply peers after exit node change", "error", err)
		return err
	}
	if proxyuplink.ActiveServer() != nil {
		proxyuplink.RefreshTCPPeerRoutes()
	}
	user, tenant := uiapi.SessionIdentity()
	if pull.ChangeDefaultGw && config.AnyNodeConnected() {
		gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
		if !wireguard.GetIGWMonitor().IsCurrentIGW(gw4, gw6) {
			igw, ok := wireguard.FindInternetGwPeer(pull.Peers, gw4, gw6)
			if !ok {
				err := fmt.Errorf("internet gateway peer not found after exit node change")
				slog.Warn(err.Error())
				return err
			}
			_ = wireguard.RestoreInternetGw()
			if err := wireguard.SetInternetGw(igw.PublicKey.String(), gw4, gw6); err != nil {
				slog.Error("error setting default gateway after exit node change", "error", err)
				return err
			}
		} else {
			wireguard.RefreshInternetGwHostPins()
		}
		_ = config.SetDesiredWantIGW(user, tenant, true)
	} else if len(config.Netclient().CurrGwNmIP) > 0 || len(config.Netclient().CurrGwNmIP6) > 0 {
		if err := wireguard.RestoreInternetGw(); err != nil {
			slog.Error("error restoring default gateway after exit node clear", "error", err)
			return err
		}
		_ = config.SetDesiredWantIGW(user, tenant, false)
	}
	if len(pull.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pull.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pull.EgressRoutes)
	} else {
		wireguard.RemoveEgressRoutes()
		wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{})
	}
	return nil
}

var pullForReconnect = PullForDesktop

const (
	reconnectPullTimeout  = 10 * time.Second
	reconnectPullInterval = 250 * time.Millisecond
)

func hostPullHasConnectedNetworks(pull models.HostPull, networks []string) bool {
	if len(networks) == 0 {
		return false
	}
	byNet := make(map[string]models.Node, len(pull.Nodes))
	for _, node := range pull.Nodes {
		byNet[node.Network] = node
	}
	for _, network := range networks {
		node, ok := byNet[network]
		if !ok || !node.Connected {
			return false
		}
	}
	return true
}

func hostPullReadyForReconnect(pull models.HostPull, networks []string, wantIGW bool) bool {
	if !hostPullHasConnectedNetworks(pull, networks) {
		return false
	}
	if !wantIGW {
		return true
	}
	if !pull.ChangeDefaultGw {
		return false
	}
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	if gw4 == nil && gw6 == nil {
		return false
	}
	_, ok := wireguard.FindInternetGwPeer(pull.Peers, gw4, gw6)
	return ok
}

func waitForReconnectHostPull(networks []string, wantIGW bool) (models.HostPull, error) {
	var last models.HostPull
	var lastErr error
	deadline := time.Now().Add(reconnectPullTimeout)
	for attempt := 1; ; attempt++ {
		resp, _, _, err := pullForReconnect(false, true)
		if err != nil {
			lastErr = err
			slog.Warn("failed to pull after reconnect", "attempt", attempt, "error", err)
		} else {
			last = resp
			lastErr = nil
			if hostPullReadyForReconnect(resp, networks, wantIGW) {
				return resp, nil
			}
			slog.Info("host pull has not reflected reconnect yet",
				"attempt", attempt, "want_igw", wantIGW, "change_default_gw", resp.ChangeDefaultGw)
		}
		if time.Now().Add(reconnectPullInterval).After(deadline) {
			break
		}
		time.Sleep(reconnectPullInterval)
	}
	if lastErr != nil {
		return last, lastErr
	}
	if wantIGW {
		return last, fmt.Errorf("host pull has not reflected exit-node routing after reconnect")
	}
	return last, fmt.Errorf("host pull has not reflected connected networks after reconnect")
}

// applyReconnectInProcess brings the live iface and exit routes up without a
// daemon SIGHUP (hole-punch + iface recreate is what delayed internet after login).
func applyReconnectInProcess(pull models.HostPull, wantIGW bool) error {
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	if err := nc.Configure(); err != nil {
		slog.Warn("configure iface after reconnect failed; trying create", "error", err)
		if err := nc.Create(); err != nil {
			return err
		}
		if err := nc.Configure(); err != nil {
			return err
		}
	}
	if len(pull.Peers) > 0 {
		config.UpdateHostPeers(pull.Peers)
	}
	if err := wireguard.SetPeers(true); err != nil {
		return err
	}
	if proxyuplink.ActiveServer() != nil {
		proxyuplink.RefreshTCPPeerRoutes()
	}
	if len(pull.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pull.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pull.EgressRoutes)
	} else if len(pull.Nodes) > 0 {
		wireguard.RemoveEgressRoutes()
		wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{})
	}
	if wantIGW || pull.ChangeDefaultGw {
		applyInternetGwAfterReconnect(pull, nil)
	}
	return nil
}

func applyInternetGwAfterReconnect(pull models.HostPull, pullErr error) {
	if !config.AnyNodeConnected() {
		return
	}
	user, tenant := uiapi.SessionIdentity()
	wantIGW := config.GetDesiredWantIGW(user, tenant)
	if pullErr == nil && pull.ChangeDefaultGw {
		// Server already advertised an exit; reinstall OS routes after iface recreate.
	} else if !(wantIGW && locallyConnectedDesired()) {
		return
	}
	var lastErr error
	resp := pull
	for attempt := 1; attempt <= 12; attempt++ {
		if attempt > 1 {
			time.Sleep(150 * time.Millisecond)
			if p, _, _, err := pullForReconnect(false, true); err == nil {
				resp = p
				config.UpdateHostPeers(p.Peers)
				_ = wireguard.SetPeers(true)
			}
		}
		if err := forceApplyInternetGw(resp); err != nil {
			lastErr = err
			slog.Info("retrying exit-node routes after reconnect",
				"attempt", attempt, "error", err)
			continue
		}
		_ = config.SetDesiredWantIGW(user, tenant, true)
		kickInternetGwHandshake(resp)
		return
	}
	if lastErr != nil {
		slog.Warn("failed to apply exit-node routes after reconnect", "error", lastErr)
	}
}

func locallyConnectedDesired() bool {
	if !uiapi.IsSessionActive() {
		return false
	}
	user, tenant := uiapi.SessionIdentity()
	desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
	nodes := config.GetNodes()
	for _, network := range desired {
		if node, ok := nodes[network]; ok && node.Connected {
			return true
		}
	}
	return false
}

func forceApplyInternetGw(pull models.HostPull) error {
	if !pull.ChangeDefaultGw {
		return fmt.Errorf("change_default_gw is false")
	}
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	if gw4 == nil && gw6 == nil {
		return fmt.Errorf("missing internet gateway nexthop")
	}
	igw, ok := wireguard.FindInternetGwPeer(pull.Peers, gw4, gw6)
	if !ok {
		igw, ok = wireguard.FindInternetGwPeer(config.Netclient().HostPeers, gw4, gw6)
	}
	if !ok {
		return fmt.Errorf("internet gateway peer not found")
	}
	_ = wireguard.RestoreInternetGw()
	if err := wireguard.SetInternetGw(igw.PublicKey.String(), gw4, gw6); err != nil {
		return err
	}
	return nil
}

func kickInternetGwHandshake(pull models.HostPull) {
	gw4, gw6 := wireguard.NormalizeIGWNexthops(pull.DefaultGwIp, pull.DefaultGwIp6)
	ip := gw4
	if len(ip) == 0 {
		ip = gw6
	}
	if len(ip) == 0 {
		return
	}
	go func() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "443"), 2*time.Second)
		if err == nil {
			_ = conn.Close()
		}
	}()
}

func refreshHostPullAfterReconnect(prev models.HostPull, prevErr error) (models.HostPull, error) {
	if !uiapi.IsSessionActive() {
		return prev, prevErr
	}
	user, tenant := uiapi.SessionIdentity()
	desired := filterDesiredNetworks(config.GetDesiredNetworks(user, tenant), uiapi.RestrictToSingleNetwork())
	if len(desired) == 0 {
		return prev, prevErr
	}
	nodes := config.GetNodes()
	anyConnected := false
	for _, network := range desired {
		if node, ok := nodes[network]; ok && node.Connected {
			anyConnected = true
			break
		}
	}
	if !anyConnected {
		return prev, prevErr
	}
	wantIGW := config.GetDesiredWantIGW(user, tenant)
	if prevErr == nil && hostPullReadyForReconnect(prev, desired, wantIGW) {
		return prev, nil
	}
	resp, err := waitForReconnectHostPull(desired, wantIGW)
	if err != nil {
		if prevErr == nil && (resp.ChangeDefaultGw || hostPullHasConnectedNetworks(resp, desired)) {
			return resp, nil
		}
		if prevErr == nil {
			return prev, prevErr
		}
		return resp, err
	}
	return resp, nil
}

func ipCopy(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func ipEqual(a, b net.IP) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return a.Equal(b)
}
