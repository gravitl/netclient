package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/sys/windows"
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
	igw           wgtypes.PeerConfig
	peerNetworkIP net.IP
	ctx           context.Context
	ticker        *time.Ticker
	isIPv4        bool
	isIPv6        bool
	isHealthy     bool
	successCount  int
	failureCount  int
}

var igwMonitorCancelFunc context.CancelFunc

func startIGWMonitor(igw wgtypes.PeerConfig, peerNetworkIP net.IP) {
	// ideally, it should never happen that we have multiple
	// internet gateways, but just in case it happens, we need to
	// stop the monitor for the other internet gateway.
	if igwMonitorCancelFunc != nil {
		igwMonitorCancelFunc()
	}

	var ctx context.Context
	ctx, igwMonitorCancelFunc = context.WithCancel(context.Background())

	var isIPv4, isIPv6 bool
	for _, allowedIP := range igw.AllowedIPs {
		if allowedIP.String() == IPv4Network {
			isIPv4 = true
		}

		if allowedIP.String() == IPv6Network {
			isIPv6 = true
		}
	}

	status := &igwStatus{
		igw:           igw,
		peerNetworkIP: peerNetworkIP,
		ctx:           ctx,
		ticker:        time.NewTicker(IGWMonitorInterval),
		isIPv4:        isIPv4,
		isIPv6:        isIPv6,
		isHealthy:     true, // Assume healthy initially
	}

	go func(igwStatus *igwStatus) {
		logger.Log(0, "starting health monitor for internet gateway endpoint", igw.Endpoint.String())

		for {
			select {
			case <-igwStatus.ctx.Done():
				logger.Log(0, "exiting health monitor for internet gateway endpoint", igw.Endpoint.String())
				return
			case <-igwStatus.ticker.C:
				logger.Log(0, "checking health of internet gateway endpoint", igw.Endpoint.String())
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
	reachable := isHostReachable(igwStatus.igw.Endpoint.IP, igwStatus.igw.Endpoint.Port)
	if reachable {
		logger.Log(0, "internet gateway detected up", igwStatus.igw.Endpoint.String())

		igwStatus.successCount++
		igwStatus.failureCount = 0

		if !igwStatus.isHealthy && igwStatus.successCount >= IGWRecoveryThreshold {
			logger.Log(0, "setting internet gateway healthy", igwStatus.igw.Endpoint.String())
			igwStatus.isHealthy = true

			logger.Log(0, "restoring default routes for internet gateway endpoint", igwStatus.igw.Endpoint.String())
			// internet gateway is back up, restore 0.0.0.0/0 and ::/0 routes
			err := restoreDefaultRoutesOnIGWPeer(igwStatus.igw, igwStatus.isIPv4, igwStatus.isIPv6)
			if err != nil {
				logger.Log(0, "failed to restore default routes for internet gateway endpoint %s: %v", igwStatus.igw.Endpoint.String(), err.Error())
			}

			logger.Log(0, "setting default routes on host")
			err = setDefaultRoutesOnHost(igwStatus.peerNetworkIP)
		}
	} else {
		logger.Log(0, "internet gateway detected down", igwStatus.igw.Endpoint.String())

		igwStatus.failureCount++
		igwStatus.successCount = 0

		if igwStatus.isHealthy && igwStatus.failureCount >= IGWFailureThreshold {
			logger.Log(0, "setting internet gateway unhealthy", igwStatus.igw.Endpoint.String())
			igwStatus.isHealthy = false

			logger.Log(0, "removing default routes for internet gateway endpoint", igwStatus.igw.Endpoint.String())
			// internet gateway is down, remove 0.0.0.0/0 and ::/0 routes
			err := removeDefaultRoutesOnIGWPeer(igwStatus.igw)
			if err != nil {
				logger.Log(0, "failed to remove default routes for internet gateway endpoint %s: %v", igwStatus.igw.Endpoint.String(), err.Error())
			}

			logger.Log(0, "resetting default routes on host")
			err = resetDefaultRoutesOnHost()
			if err != nil {
				logger.Log(0, "failed to reset default routes on host: %v", err.Error())
			}
		}
	}
}

// removeDefaultRoutesOnIGWPeer removes default routes (0.0.0.0/0,::/0)
// from the internet gateway peer.
func removeDefaultRoutesOnIGWPeer(igw wgtypes.PeerConfig) error {
	peer, err := GetPeer(ncutils.GetInterfaceName(), igw.PublicKey.String())
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}

	newAllowedIPs := make([]net.IPNet, 0)
	for _, allowedIP := range peer.AllowedIPs {
		if allowedIP.String() != IPv4Network && allowedIP.String() != IPv6Network {
			newAllowedIPs = append(newAllowedIPs, allowedIP)
		}
	}

	return UpdatePeer(&wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		AllowedIPs:        newAllowedIPs,
		ReplaceAllowedIPs: true,
		UpdateOnly:        true,
	})
}

// restoreDefaultRoutesOnIGWPeer restores default routes (0.0.0.0/0,::/0)
// to the internet gateway peer.
func restoreDefaultRoutesOnIGWPeer(igw wgtypes.PeerConfig, isIPv4, isIPV6 bool) error {
	peer, err := GetPeer(ncutils.GetInterfaceName(), igw.PublicKey.String())
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}

	var ipv4Present, ipv6Present bool
	newAllowedIPs := peer.AllowedIPs
	for _, allowedIP := range newAllowedIPs {
		if allowedIP.String() == IPv4Network {
			ipv4Present = true
		}

		if allowedIP.String() == IPv6Network {
			ipv6Present = true
		}
	}

	if isIPv4 && !ipv4Present {
		_, ipv4Net, _ := net.ParseCIDR(IPv4Network)
		newAllowedIPs = append(newAllowedIPs, *ipv4Net)
	}

	if isIPV6 && !ipv6Present {
		_, ipv6Net, _ := net.ParseCIDR(IPv6Network)
		newAllowedIPs = append(newAllowedIPs, *ipv6Net)
	}

	return UpdatePeer(&wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		AllowedIPs:        newAllowedIPs,
		ReplaceAllowedIPs: true,
		UpdateOnly:        true,
	})
}

func isHostReachable(ip net.IP, port int) bool {
	address := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", address, IGWDialTimeout)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && errors.Is(errno, syscall.ECONNREFUSED) {
			// if the internet gateway responded with ECONNREFUSED, it means
			// that it is reachable
			return true
		}

		// windows returns a different error code for ECONNREFUSED
		var winerrno windows.Errno
		if errors.As(err, &winerrno) && errors.Is(winerrno, windows.WSAECONNREFUSED) {
			return true
		}
	} else {
		_ = conn.Close()
		return true
	}

	return false
}
