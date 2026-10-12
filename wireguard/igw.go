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
	IGWDialTimeout = time.Second * 2
	// IGWMonitorInterval is the interval at which to check internet gateway's health.
	// With IGWFailureThreshold samples this is ~15s to declare the exit unhealthy
	// and trigger auto-exit failover — fast enough for UX, slow enough to ride
	// out brief wifi blips.
	IGWMonitorInterval = time.Second * 5
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
	// IGWPinRefreshInterval is how often underlay pins are reconciled against
	// the LAN gateway while the exit is active, and how often missing exit
	// default routes are put back after an ISP change. A multi-second gap
	// black-holes traffic that is still pointed at the exit, so this stays
	// short enough that the switch feels like a brief hitch.
	IGWPinRefreshInterval = time.Second
	// defaultMetricsPort mirrors networking.InitialiseIfaceMetricsServer's fallback.
	defaultMetricsPort = 51821
)

var (
	igwMonitor *IGWMonitor
	once       sync.Once
)

// OnIGWUnhealthy is invoked after exit default routes are torn down because the
// IGW health monitor marked the gateway unhealthy. Optional; the functions
// package registers auto-exit failover here. Called asynchronously.
var OnIGWUnhealthy func(publicKey string)

// OnIGWRoutingChanged is invoked after the health monitor installs or removes
// exit default routes. OS DNS follows CurrGwNmIP (system-wide while an exit is
// up, split otherwise), so it has to be reapplied on every flip or the host
// keeps sending all queries to a resolver that no longer forwards them.
// Optional; the functions package registers the DNS reapply here. Runs before
// OnIGWUnhealthy, on the same goroutine, because failover needs working DNS.
var OnIGWRoutingChanged func()

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
	// probeEverSucceeded records that this gateway has answered a probe at least
	// once, which means it is a gateway whose silence is meaningful. Gateways that
	// never answer (no metrics listener, firewalled) stay on passive evidence.
	probeEverSucceeded bool
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

		healthTicker := time.NewTicker(IGWMonitorInterval)
		routeTicker := time.NewTicker(IGWPinRefreshInterval)
		defer healthTicker.Stop()
		defer routeTicker.Stop()

		// The reachability probe blocks for up to IGWDialTimeout. Route repair
		// runs on this goroutine; the probe result comes back on probeCh so a
		// dial cannot postpone fixing the underlay after an ISP change.
		probeCh := make(chan igwSample, 1)
		var probing bool

		// Repair once immediately. The ticker's first fire is a full interval
		// later, and the exit may already be pointed at a gateway that is gone.
		refreshHealthyExitRoutes(s)

		for {
			select {
			case <-ctx.Done():
				logger.Log(0, "stopping health monitor for internet gateway")
				return
			case <-routeTicker.C:
				if ifaceRebuilds.Load() > 0 {
					continue
				}
				refreshHealthyExitRoutes(s)
			case <-healthTicker.C:
				if probing || ifaceRebuilds.Load() > 0 {
					logger.Log(2, "internet gateway health: skipping check")
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
				probing = true
				go func() {
					probeCh <- s.collectSample()
				}()
			case sample := <-probeCh:
				probing = false
				if ctx.Err() != nil {
					return
				}
				if ifaceRebuilds.Load() > 0 {
					logger.Log(2, "internet gateway health: iface rebuild in flight, dropping sample")
					continue
				}
				logger.Log(2, "checking health of internet gateway...")
				s.applySample(sample)
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

// exitRoutesWinning reports whether an external lookup still egresses via the
// exit. An ISP change can delete or outrank those routes while the tunnel
// itself stays up. Tests replace this.
var exitRoutesWinning = defaultExitRoutesWinning

// reinstallExitRoutes puts the host default route back on the exit without
// restarting the health monitor. Tests replace this.
var reinstallExitRoutes = defaultReinstallExitRoutes

// pinExitUnderlay reconciles LAN pins for the exit handshake. Tests replace this.
var pinExitUnderlay = pinInternetGwHostRoutes

// currentUnderlayGateway is the LAN gateway pins were last pointed at.
// Tests replace this.
var currentUnderlayGateway = underlayGatewayKey

// refreshHealthyExitRoutes runs while the exit is healthy. It re-points
// underlay pins, then reinstalls host exit routes when they no longer win
// the default lookup. Unhealthy status returns immediately so the LAN default
// installed by setUnhealthy stays in place. A gateway move clears the failure
// streak: probes taken while the old ISP was already dead must not spend the
// budget that would pull the exit down for IGWRecoveryThreshold more samples.
func refreshHealthyExitRoutes(s *igwStatus) bool {
	if s == nil || !s.isHealthy {
		return false
	}
	before := currentUnderlayGateway()
	pinExitUnderlay(s.publicKey)
	moved := currentUnderlayGateway() != before
	if moved {
		s.failureCount = 0
	}
	if exitRoutesWinning(s.gw4, s.gw6) {
		return moved
	}
	logger.Log(0, "exit default routes lost after network change; reinstalling")
	if err := reinstallExitRoutes(s.publicKey, s.gw4, s.gw6); err != nil {
		logger.Log(0, "failed to reinstall exit default routes:", err.Error())
	}
	return true
}

func underlayGatewayKey() string {
	nc := config.Netclient()
	if nc == nil {
		return ""
	}
	v4, v6 := "", ""
	if len(nc.OriginalDefaultGatewayIp) > 0 {
		v4 = nc.OriginalDefaultGatewayIp.String()
	}
	if len(nc.OriginalDefaultGatewayIp6) > 0 {
		v6 = nc.OriginalDefaultGatewayIp6.String()
	}
	return v4 + "," + v6
}

// dialIP returns the preferred nexthop for health checks (IPv4 preferred).
func (s *igwStatus) dialIP() net.IP {
	if len(s.gw4) > 0 {
		return s.gw4
	}
	return s.gw6
}

// igwSample is one health observation. collectSample may block on the probe;
// applySample is the part that changes routes and must stay on the monitor
// goroutine alongside route repair.
type igwSample struct {
	peerErr   error
	igw       wgtypes.Peer
	rxMoved   bool
	hasAddr   bool
	canProbe  bool
	probed    bool
	reachable bool
}

// check verifies whether the internet gateway is reachable and updates its
// status, adjusting routes on the host accordingly.
func (s *igwStatus) check() {
	s.applySample(s.collectSample())
}

func (s *igwStatus) collectSample() igwSample {
	var sample igwSample
	igw, err := GetPeer(ncutils.GetInterfaceName(), s.publicKey)
	if err != nil {
		sample.peerErr = err
		return sample
	}
	sample.igw = igw
	// Take the rx baseline every tick, whether or not it ends up being the signal
	// that decides this sample.
	sample.rxMoved = s.noteRx(igw.ReceiveBytes)
	sample.canProbe = s.dialIP() != nil
	sample.hasAddr = ifaceHasSourceAddr()
	if !sample.hasAddr || !sample.canProbe {
		return sample
	}
	sample.probed = true
	sample.reachable = s.probeGateway()
	return sample
}

func (s *igwStatus) applySample(sample igwSample) {
	if sample.peerErr != nil {
		logger.Log(0, "failed to get internet gateway peer:", sample.peerErr.Error())
		if errors.Is(sample.peerErr, ErrPeerNotFound) {
			// A missing peer on a live device is usually an iface rebuild we did not
			// see, so count it like any other failed sample rather than tearing exit
			// routing down on one miss.
			s.noteFailure(nil)
		}
		return
	}

	// Every passive signal below is measured on the underlay: handshakes and
	// keepalives keep completing against the peer's endpoint even when the tunnel
	// cannot carry a single packet. Without a local overlay address there is
	// nothing to source traffic from, so the exit path is broken no matter how
	// alive the peer looks. This has to be checked before the probe, because the
	// probe can never succeed in this state either — leaving probeEverSucceeded
	// false and pinning the gateway on passive evidence forever, which is how a
	// dead exit once held the default route indefinitely.
	//
	// Iface rebuilds pass through here with no address; the rebuild counter and
	// the re-armed startup grace above keep those windows from counting.
	if !sample.hasAddr {
		logger.Log(0, "internet gateway unusable: netmaker interface has no address to source traffic from")
		s.noteFailure(&sample.igw)
		return
	}

	// The probe is the only signal that tests the path *through* the tunnel: it
	// reaches the gateway's endpoint-detection listener over the overlay. The
	// passive signals are weaker than they look — WireGuard keepalives and rekeys
	// keep both the receive counter and the handshake timestamp moving while the
	// exit has stopped forwarding, so trusting them let a black-holed exit look
	// healthy indefinitely while the host had no internet at all.
	//
	// So probe first, every sample. Once a gateway has answered a probe we know it
	// answers, and from then on its silence is real evidence of a broken path that
	// no passive counter may vouch for.
	if sample.canProbe {
		if sample.probed && sample.reachable {
			s.probeEverSucceeded = true
			s.noteSuccess(sample.igw)
			return
		}
		if s.probeEverSucceeded {
			logger.Log(2, "internet gateway probe failed on a gateway that has answered before")
			s.noteFailure(&sample.igw)
			return
		}
	}

	// Either there is nothing to probe, or this gateway has never answered one
	// (no metrics listener, firewalled). Passive evidence is all we have, and
	// tearing exit routing down on its absence alone would be wrong here.
	if sample.rxMoved || s.handshakeFresh(sample.igw) {
		s.noteSuccess(sample.igw)
		return
	}
	if !sample.canProbe {
		// Nothing to probe and nothing has spoken: no evidence either way.
		return
	}

	s.noteFailure(&sample.igw)
}

// noteSuccess records one healthy sample, restoring exit routes once
// IGWRecoveryThreshold consecutive samples have passed.
func (s *igwStatus) noteSuccess(igw wgtypes.Peer) {
	logger.Log(2, "internet gateway detected up")

	s.successCount++
	s.failureCount = 0

	if !s.isHealthy && s.successCount >= IGWRecoveryThreshold {
		s.setHealthy(igw)
	}
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

	if hook := OnIGWRoutingChanged; hook != nil {
		go hook()
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

	// LAN is restored — auto-exit failover (if registered) can reach the API
	// once DNS has dropped back to split mode.
	routingHook, unhealthyHook := OnIGWRoutingChanged, OnIGWUnhealthy
	if routingHook == nil && unhealthyHook == nil {
		return
	}
	pk := s.publicKey
	go func() {
		if routingHook != nil {
			routingHook()
		}
		if unhealthyHook != nil {
			unhealthyHook(pk)
		}
	}()
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
