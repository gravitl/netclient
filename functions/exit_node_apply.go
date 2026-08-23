package functions

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/internal/proxyuplink"
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
	if pull.ChangeDefaultGw {
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
		}
	} else if len(config.Netclient().CurrGwNmIP) > 0 || len(config.Netclient().CurrGwNmIP6) > 0 {
		if err := wireguard.RestoreInternetGw(); err != nil {
			slog.Error("error restoring default gateway after exit node clear", "error", err)
			return err
		}
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
