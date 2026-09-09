package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// IGWDialTimeout is the timeout for dialing internet gateway. Kept well inside
	// IGWMonitorInterval so a failing probe cannot stretch the sampling period.
	IGWDialTimeout = time.Second * 3
	// IGWMonitorInterval is the interval at which to check internet gateway's health.
	// While the exit node is down the host has no internet at all, so samples are
	// taken often enough that IGWFailureThreshold of them is still seconds, not
	// minutes.
	IGWMonitorInterval = time.Second * 10
	// IGWRecoveryThreshold is the number of consecutive successes before considering
	// internet gateway is up.
	IGWRecoveryThreshold = 3
	// IGWFailureThreshold is the number of consecutive failures before considering
	// internet gateway is down.
	IGWFailureThreshold = 3
	// IGWHandshakeFreshness is how recent a WireGuard handshake must be to count as
	// proof of life on its own. It has to stay short: a handshake as old as
	// WireGuard's rekey period would keep a gateway that died seconds ago looking
	// healthy for minutes, which is exactly the outage this monitor exists to end.
	IGWHandshakeFreshness = 90 * time.Second
	// IGWStartupGrace skips failure counting briefly after monitor start so the
	// first handshake can complete. It only has to cover monitor start through
	// first handshake — BeginIfaceRebuild covers rebuilds — and it is re-armed
	// after every rebuild, so a long grace compounds into real blindness.
	IGWStartupGrace = 45 * time.Second
	// defaultMetricsPort mirrors networking.InitialiseIfaceMetricsServer's fallback.
	defaultMetricsPort = 51821
)

var (
	igwMonitor *IGWMonitor
	once       sync.Once
)

var (
	// ifaceRebuilds is non-zero while the netmaker iface is being torn down and
	// rebuilt. Between Create and Configure the device is up with no peers at all,
	// which is indistinguishable from the exit peer vanishing, so health checks
	// must not run.
	ifaceRebuilds atomic.Int64
	// igwRearmPending re-arms the startup grace on the first check after a rebuild.
	igwRearmPending atomic.Bool
)

// BeginIfaceRebuild pauses internet gateway health checks for the duration of an
// iface teardown and rebuild. The returned func must be called once the iface is
// configured again; calling it more than once is safe.
func BeginIfaceRebuild() func() {
	ifaceRebuilds.Add(1)
	var done sync.Once
	return func() {
		done.Do(func() {
			if ifaceRebuilds.Add(-1) == 0 {
				igwRearmPending.Store(true)
			}
		})
	}
}

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
	startedAt    time.Time
	// lastRx is the exit peer's receive counter at the previous sample, or -1 when
	// no baseline has been taken yet.
	lastRx int64
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
		startedAt: time.Now(),
		lastRx:    -1,
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
				if ifaceRebuilds.Load() > 0 {
					logger.Log(2, "internet gateway health: iface rebuild in flight, skipping check")
					continue
				}
				// Peers were just reapplied and no handshake has happened yet, so
				// give the tunnel the same slack as a fresh monitor.
				if igwRearmPending.Swap(false) {
					s.startedAt = time.Now()
					s.successCount = 0
					s.failureCount = 0
					s.lastRx = -1
				}
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
			// A missing peer on a live device is usually an iface rebuild we did not
			// see, so count it like any other failed sample rather than tearing exit
			// routing down on one miss.
			s.noteFailure(nil)
		}

		return
	}

	// Take the rx baseline every tick, whether or not it ends up being the signal
	// that decides this sample.
	rxMoved := s.noteRx(igw.ReceiveBytes)

	if s.dialIP() == nil && !rxMoved && !s.handshakeFresh(igw) {
		// Nothing to probe and nothing has spoken: no evidence either way.
		return
	}

	// Cheapest evidence first, and each of these is proof on its own. Bytes
	// decrypted from the exit peer can only have come from the peer, a recent
	// handshake proves the underlay worked whatever it is (UDP or a TCP uplink),
	// and the probe reaches the peer's endpoint-detection listener through the
	// tunnel. The probe only runs when the passive signals are silent.
	if rxMoved || s.handshakeFresh(igw) || s.probeGateway() {
		logger.Log(2, "internet gateway detected up")

		s.successCount++
		s.failureCount = 0

		if !s.isHealthy && s.successCount >= IGWRecoveryThreshold {
			s.setHealthy(igw)
		}
		return
	}

	s.noteFailure(&igw)
}

// handshakeFresh reports whether the exit peer completed a handshake recently
// enough to count as proof of life.
func (s *igwStatus) handshakeFresh(igw wgtypes.Peer) bool {
	return !igw.LastHandshakeTime.IsZero() && time.Since(igw.LastHandshakeTime) <= IGWHandshakeFreshness
}

// noteRx records the exit peer's receive counter and reports whether it advanced
// since the previous sample. Only the exit peer's key can produce those bytes, so
// an advance is proof of life that needs nothing listening on the gateway.
func (s *igwStatus) noteRx(rx int64) bool {
	prev := s.lastRx
	s.lastRx = rx
	// No baseline yet, or a counter reset by an iface rebuild: not evidence either way.
	if prev < 0 || rx < prev {
		return false
	}
	return rx > prev
}

// probeGateway connects to the exit gateway's endpoint-detection listener over
// the overlay, which every netclient runs, so a live gateway answers through the
// tunnel. The old probe used the peer's WireGuard port, where nothing listens on
// TCP: it could only ever succeed when the gateway's firewall happened to answer
// with an RST, and timed out as a false failure otherwise.
func (s *igwStatus) probeGateway() bool {
	ip := s.dialIP()
	if ip == nil {
		return false
	}
	return isHostReachable(ip, igwProbePort())
}

// igwProbePort mirrors networking.InitialiseIfaceMetricsServer's port choice.
func igwProbePort() int {
	if server := config.GetServer(config.CurrServer); server != nil && server.MetricsPort > 0 {
		return server.MetricsPort
	}
	return defaultMetricsPort
}

// noteFailure records one failed health sample, tearing down exit routes once
// IGWFailureThreshold consecutive samples have failed. igw is nil when the exit
// peer could not be read at all.
func (s *igwStatus) noteFailure(igw *wgtypes.Peer) {
	if time.Since(s.startedAt) < IGWStartupGrace {
		logger.Log(2, "internet gateway health: still in startup grace, not counting failure")
		return
	}

	logger.Log(2, "internet gateway detected down")

	s.failureCount++
	s.successCount = 0

	if s.isHealthy && s.failureCount >= IGWFailureThreshold {
		s.setUnhealthy(igw)
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

func (s *igwStatus) setUnhealthy(igw *wgtypes.Peer) {
	if !s.isHealthy {
		return
	}

	logger.Log(0, "setting internet gateway unhealthy")
	s.isHealthy = false

	// Only rewrite AllowedIPs from a peer that was actually read: a synthesized one
	// carries no AllowedIPs, and replacing the list with an empty set would strip
	// the exit peer of its overlay routes too.
	if igw != nil {
		logger.Log(0, "removing default routes for internet gateway")
		// internet gateway is down, remove 0.0.0.0/0 and ::/0 routes
		if err := removeDefaultRoutesOnIGWPeer(*igw); err != nil {
			logger.Log(0, "failed to remove default routes for internet gateway:", err.Error())
		}
	}

	logger.Log(0, "resetting default routes on host")
	if err := resetDefaultRoutesOnHost(); err != nil {
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
