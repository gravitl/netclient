package wireguard

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// IGWDialTimeout is the timeout for dialing internet gateway.
	IGWDialTimeout = time.Second * 5
	// IGWMonitorInterval is the interval at which to check internet gateway's health.
	IGWMonitorInterval = time.Second * 30
	// IGWRecoveryThreshold is the number of consecutive successes before considering
	// internet gateway is up.
	IGWRecoveryThreshold = 3
	// IGWFailureThreshold is the number of consecutive failures before considering
	// internet gateway is down.
	IGWFailureThreshold = 3
)

type igwStatus struct {
	networkIP    net.IP
	publicKey    string
	ctx          context.Context
	ticker       *time.Ticker
	isHealthy    bool
	successCount int
	failureCount int
}

var igwMonitorCancelFunc context.CancelFunc

func startIGWMonitor(publicKey string, networkIP net.IP) {
	// ideally, it should never happen that we have multiple
	// internet gateways, but just in case it happens, we need to
	// stop the monitor for the other internet gateway.
	if igwMonitorCancelFunc != nil {
		igwMonitorCancelFunc()
	}

	var ctx context.Context
	ctx, igwMonitorCancelFunc = context.WithCancel(context.Background())

	status := &igwStatus{
		networkIP: networkIP,
		publicKey: publicKey,
		ctx:       ctx,
		ticker:    time.NewTicker(IGWMonitorInterval),
		isHealthy: true, // Assume healthy initially
	}

	go func(igwStatus *igwStatus) {
		logger.Log(0, "starting health monitor for internet gateway")

		for {
			select {
			case <-igwStatus.ctx.Done():
				logger.Log(0, "stopping health monitor for internet gateway")
				return
			case <-igwStatus.ticker.C:
				logger.Log(2, "checking health of internet gateway...")
				checkIGWStatus(igwStatus)
			}
		}
	}(status)
}

func stopIGWMonitor() {
	if igwMonitorCancelFunc != nil {
		igwMonitorCancelFunc()
	}
}

func checkIGWStatus(igwStatus *igwStatus) {
	igw, err := GetPeer(ncutils.GetInterfaceName(), igwStatus.publicKey)
	if err != nil {
		logger.Log(0, "failed to get internet gateway peer:", err.Error())
		return
	}

	reachable := isHostReachable(igwStatus.networkIP, igw.Endpoint.Port)
	if reachable {
		logger.Log(2, "internet gateway detected up")

		igwStatus.successCount++
		igwStatus.failureCount = 0

		if !igwStatus.isHealthy && igwStatus.successCount >= IGWRecoveryThreshold {
			logger.Log(2, "setting internet gateway healthy")
			igwStatus.isHealthy = true

			logger.Log(2, "restoring default routes for internet gateway")
			// internet gateway is back up, restore 0.0.0.0/0 and ::/0 routes
			err := restoreDefaultRoutesOnIGWPeer(igw, igwStatus.networkIP)
			if err != nil {
				logger.Log(0, "failed to restore default routes for internet gateway:", err.Error())
			}

			logger.Log(2, "setting default routes on host")
			err = setDefaultRoutesOnHost(igwStatus.publicKey, igwStatus.networkIP)
			if err != nil {
				logger.Log(0, "failed to set default routes on host:", err.Error())
			}
		}
	} else {
		logger.Log(2, "internet gateway detected down")

		igwStatus.failureCount++
		igwStatus.successCount = 0

		if igwStatus.isHealthy && igwStatus.failureCount >= IGWFailureThreshold {
			logger.Log(2, "setting internet gateway unhealthy")
			igwStatus.isHealthy = false

			logger.Log(2, "removing default routes for internet gateway")
			// internet gateway is down, remove 0.0.0.0/0 and ::/0 routes
			err := removeDefaultRoutesOnIGWPeer(igw)
			if err != nil {
				logger.Log(0, "failed to remove default routes for internet gateway:", err.Error())
			}

			logger.Log(2, "resetting default routes on host")
			err = resetDefaultRoutesOnHost()
			if err != nil {
				logger.Log(0, "failed to reset default routes on host:", err.Error())
			}
		}
	}
}

// restoreDefaultRoutesOnIGWPeer restores default routes (0.0.0.0/0,::/0)
// to the internet gateway peer.
func restoreDefaultRoutesOnIGWPeer(igw wgtypes.Peer, networkIP net.IP) error {
	var ipv4Present, ipv6Present bool
	newAllowedIPs := igw.AllowedIPs
	for _, allowedIP := range newAllowedIPs {
		if allowedIP.String() == IPv4Network {
			ipv4Present = true
		}

		if allowedIP.String() == IPv6Network {
			ipv6Present = true
		}
	}

	isIPv4 := networkIP.To4() != nil
	isIPV6 := networkIP.To4() == nil

	if isIPv4 && !ipv4Present {
		_, ipv4Net, _ := net.ParseCIDR(IPv4Network)
		newAllowedIPs = append(newAllowedIPs, *ipv4Net)
	}

	if isIPV6 && !ipv6Present {
		_, ipv6Net, _ := net.ParseCIDR(IPv6Network)
		newAllowedIPs = append(newAllowedIPs, *ipv6Net)
	}

	return UpdatePeer(&wgtypes.PeerConfig{
		PublicKey:         igw.PublicKey,
		AllowedIPs:        newAllowedIPs,
		ReplaceAllowedIPs: true,
		UpdateOnly:        true,
	})
}

// removeDefaultRoutesOnIGWPeer removes default routes (0.0.0.0/0,::/0)
// from the internet gateway peer.
func removeDefaultRoutesOnIGWPeer(igw wgtypes.Peer) error {
	newAllowedIPs := make([]net.IPNet, 0)
	for _, allowedIP := range igw.AllowedIPs {
		if allowedIP.String() != IPv4Network && allowedIP.String() != IPv6Network {
			newAllowedIPs = append(newAllowedIPs, allowedIP)
		}
	}

	return UpdatePeer(&wgtypes.PeerConfig{
		PublicKey:         igw.PublicKey,
		AllowedIPs:        newAllowedIPs,
		ReplaceAllowedIPs: true,
		UpdateOnly:        true,
	})
}

func isHostReachable(ip net.IP, port int) bool {
	var address string
	if ip.To4() != nil {
		address = fmt.Sprintf("%s:%d", ip.String(), port)
	} else {
		address = fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	conn, err := net.DialTimeout("tcp", address, IGWDialTimeout)
	if err != nil {
		if isEconnRefused(err) {
			// if the internet gateway responded with ECONNREFUSED, it means
			// that it is reachable
			return true
		}
	} else {
		_ = conn.Close()
		return true
	}

	return false
}
