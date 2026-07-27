package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
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

var (
	igwMonitor *IGWMonitor
	once       sync.Once
)

type IGWMonitor struct {
	mu         sync.Mutex
	status     *igwStatus
	cancelFunc context.CancelFunc
}

type igwStatus struct {
	gw4          net.IP
	gw6          net.IP
	publicKey    string
	isHealthy    bool
	successCount int
	failureCount int
}

func GetIGWMonitor() *IGWMonitor {
	once.Do(func() {
		igwMonitor = &IGWMonitor{}
	})
	return igwMonitor
}

// Monitor starts the monitor for dual-stack (or single-family) internet gateway nexthops.
func (m *IGWMonitor) Monitor(publicKey string, gw4, gw6 net.IP) {
	m.mu.Lock()
	// ideally, it should never happen that we have multiple
	// internet gateways, but just in case it happens, we need to
	// stop the monitor for the other internet gateway.
	if m.cancelFunc != nil {
		m.cancelFunc()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	s := &igwStatus{
		gw4:       gw4,
		gw6:       gw6,
		publicKey: publicKey,
		isHealthy: true, // Assume healthy initially
	}
	m.status = s
	m.mu.Unlock()

	go func() {
		logger.Log(0, "starting health monitor for internet gateway")

		ticker := time.NewTicker(IGWMonitorInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Log(0, "stopping health monitor for internet gateway")
				return
			case <-ticker.C:
				logger.Log(2, "checking health of internet gateway...")
				s.check()
			}
		}
	}()
}

// Stop stops the monitor and resets its status.
func (m *IGWMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}
	m.status = nil
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

// IsCurrentIGW returns true if the configured nexthops match the current internet gateway.
func (m *IGWMonitor) IsCurrentIGW(gw4, gw6 net.IP) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status == nil {
		return false
	}

	return ipEqual(m.status.gw4, gw4) && ipEqual(m.status.gw6, gw6)
}

// dialIP returns the preferred nexthop for health checks (IPv4 preferred).
func (s *igwStatus) dialIP() net.IP {
	if len(s.gw4) > 0 {
		return s.gw4
	}
	return s.gw6
}

// check verifies whether the internet gateway is reachable and updates its
// status, adjusting routes on the host accordingly.
func (s *igwStatus) check() {
	igw, err := GetPeer(ncutils.GetInterfaceName(), s.publicKey)
	if err != nil {
		logger.Log(0, "failed to get internet gateway peer:", err.Error())

		if errors.Is(err, ErrPeerNotFound) {
			pubKey, err := wgtypes.ParseKey(s.publicKey)
			if err == nil {
				s.setUnhealthy(wgtypes.Peer{
					PublicKey: pubKey,
				})
			}
		}

		return
	}

	dialIP := s.dialIP()
	if dialIP == nil || igw.Endpoint == nil {
		return
	}

	reachable := isHostReachable(dialIP, igw.Endpoint.Port)
	if reachable {
		logger.Log(2, "internet gateway detected up")

		s.successCount++
		s.failureCount = 0

		if !s.isHealthy && s.successCount >= IGWRecoveryThreshold {
			s.setHealthy(igw)
		}
	} else {
		logger.Log(2, "internet gateway detected down")

		s.failureCount++
		s.successCount = 0

		if s.isHealthy && s.failureCount >= IGWFailureThreshold {
			s.setUnhealthy(igw)
		}
	}
}

func (s *igwStatus) setHealthy(igw wgtypes.Peer) {
	if s.isHealthy {
		return
	}

	logger.Log(0, "setting internet gateway healthy")
	s.isHealthy = true

	logger.Log(0, "restoring default routes for internet gateway")
	// internet gateway is back up, restore 0.0.0.0/0 and ::/0 routes
	err := restoreDefaultRoutesOnIGWPeer(igw, s.gw4, s.gw6)
	if err != nil {
		logger.Log(0, "failed to restore default routes for internet gateway:", err.Error())
	}

	logger.Log(0, "setting default routes on host")
	err = setDefaultRoutesOnHost(s.publicKey, s.gw4, s.gw6)
	if err != nil {
		logger.Log(0, "failed to set default routes on host:", err.Error())
	}
}

func (s *igwStatus) setUnhealthy(igw wgtypes.Peer) {
	if !s.isHealthy {
		return
	}

	logger.Log(0, "setting internet gateway unhealthy")
	s.isHealthy = false

	logger.Log(0, "removing default routes for internet gateway")
	// internet gateway is down, remove 0.0.0.0/0 and ::/0 routes
	err := removeDefaultRoutesOnIGWPeer(igw)
	if err != nil {
		logger.Log(0, "failed to remove default routes for internet gateway:", err.Error())
	}

	logger.Log(0, "resetting default routes on host")
	err = resetDefaultRoutesOnHost()
	if err != nil {
		logger.Log(0, "failed to reset default routes on host:", err.Error())
	}
}

// restoreDefaultRoutesOnIGWPeer restores default routes (0.0.0.0/0,::/0)
// to the internet gateway peer for each configured family.
func restoreDefaultRoutesOnIGWPeer(igw wgtypes.Peer, gw4, gw6 net.IP) error {
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

	if gw4 != nil && !ipv4Present {
		_, ipv4Net, _ := net.ParseCIDR(IPv4Network)
		newAllowedIPs = append(newAllowedIPs, *ipv4Net)
	}

	if gw6 != nil && !ipv6Present {
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
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
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
