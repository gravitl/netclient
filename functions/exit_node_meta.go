package functions

import (
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	//lint:ignore SA1019 Reason: same ICMP probe used for remote-access gateway latency
	"github.com/go-ping/ping"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

const (
	exitNodeProbeTimeout = time.Second
	exitNodeLatencyNone  = int64(0)
	exitNodeLatencyTO    = int64(999)
	defaultMetricsPort   = 51821
)

// attachExitNodePublicLatencies probes each exit's public AllowedEndpoints
// (ICMP + TCP 443/22). Works before the mesh is up and is used for GUI list
// ranking and Auto nearest pick.
func attachExitNodePublicLatencies(network string, nodes []models.DeviceExitNode) {
	if len(nodes) == 0 {
		return
	}
	// While an internet exit owns 0.0.0.0/0, pin every exit's public endpoints
	// on the LAN so probes and WG to alternate exits do not trombone through
	// the tunnel.
	pinIPs := exitNodeEndpointIPs(nodes)
	wireguard.SetExitNodeUnderlayPinIPs(pinIPs)
	if len(pinIPs) > 0 {
		wireguard.RefreshInternetGwHostPins()
	}

	var wg sync.WaitGroup
	resolved := 0
	for i := range nodes {
		endpoints := publicProbeHosts(nodes[i].AllowedEndpoints)
		if len(endpoints) == 0 {
			continue
		}
		resolved++
		wg.Add(1)
		go func(i int, endpoints []string) {
			defer wg.Done()
			nodes[i].LatencyMs = measurePublicLatency(endpoints)
		}(i, endpoints)
	}
	wg.Wait()
	finishExitNodeLatencyAttach(network, nodes, "public", resolved, 0)
}

// attachExitNodeOverlayLatencies probes each exit's overlay metrics port.
// Used after connect for Auto failover ranking on the mesh. Does not flip
// Status on a probe miss.
func attachExitNodeOverlayLatencies(network string, nodes []models.DeviceExitNode) {
	if len(nodes) == 0 {
		return
	}
	pinIPs := exitNodeEndpointIPs(nodes)
	wireguard.SetExitNodeUnderlayPinIPs(pinIPs)
	if len(pinIPs) > 0 {
		wireguard.RefreshInternetGwHostPins()
	}

	port := exitNodeMetricsPort()
	var wg sync.WaitGroup
	probed := 0
	for i := range nodes {
		addr := exitNodeOverlayProbeAddr(nodes[i])
		if addr == "" {
			continue
		}
		probed++
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			ok, latency := metrics.PeerConnStatus(addr, port, 1)
			if !ok {
				// One retry: right after IGW tear-down the first overlay probe
				// often times out on an otherwise healthy exit.
				ok, latency = metrics.PeerConnStatus(addr, port, 1)
			}
			if ok {
				nodes[i].LatencyMs = latency
				return
			}
			// Rank last for Auto. Do not flip Status — a single metrics-port
			// miss is not proof the peer is down.
			nodes[i].LatencyMs = exitNodeLatencyTO
		}(i, addr)
	}
	wg.Wait()
	finishExitNodeLatencyAttach(network, nodes, "overlay", probed, port)
}

func finishExitNodeLatencyAttach(network string, nodes []models.DeviceExitNode, mode string, probed int, metricsPort int) {
	origin := ""
	if nc := config.Netclient(); nc != nil {
		origin = nc.Location
	}
	markNearestExitNodes(nodes, origin)
	attrs := []any{
		"network", network,
		"nodes", len(nodes),
		"mode", mode,
		"probed", probed,
	}
	if metricsPort > 0 {
		attrs = append(attrs, "metrics_port", metricsPort)
	}
	slog.Info("exit node latencies attached", attrs...)
}

func exitNodeMetricsPort() int {
	if server := config.GetServer(config.CurrServer); server != nil && server.MetricsPort > 0 {
		return server.MetricsPort
	}
	return defaultMetricsPort
}

// exitNodeOverlayProbeAddr prefers the routing node's IPv4 overlay address,
// then IPv6 — the same preference PeerConnStatus uses for mesh metrics.
func exitNodeOverlayProbeAddr(n models.DeviceExitNode) string {
	if addr := strings.TrimSpace(n.Address); addr != "" {
		if ip := net.ParseIP(addr); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	if addr := strings.TrimSpace(n.Address6); addr != "" {
		if ip := net.ParseIP(addr); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}

func exitNodeEndpointIPs(nodes []models.DeviceExitNode) []net.IP {
	seen := map[string]struct{}{}
	var out []net.IP
	for i := range nodes {
		for _, host := range publicProbeHosts(nodes[i].AllowedEndpoints) {
			ip := net.ParseIP(host)
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

// measurePublicLatency races ICMP and TCP 443/22 against public endpoints,
// matching the remote-access gateway picker. Returns the lowest successful RTT
// within one second, or 999 on timeout.
func measurePublicLatency(endpoints []string) int64 {
	hosts := publicProbeHosts(endpoints)
	if len(hosts) == 0 {
		return exitNodeLatencyNone
	}

	type probe struct {
		ms  int64
		err error
	}
	n := 3 * len(hosts)
	ch := make(chan probe, n)
	for _, host := range hosts {
		go func(host string) {
			ms, err := tryICMP(host)
			ch <- probe{ms, err}
		}(host)
		go func(host string) {
			ms, err := tryTCP(host, 443)
			ch <- probe{ms, err}
		}(host)
		go func(host string) {
			ms, err := tryTCP(host, 22)
			ch <- probe{ms, err}
		}(host)
	}

	timeout := time.After(exitNodeProbeTimeout)
	best := exitNodeLatencyTO
	got := false
	for i := 0; i < n; i++ {
		select {
		case r := <-ch:
			if r.err == nil && r.ms > 0 && r.ms < best {
				best = r.ms
				got = true
			}
		case <-timeout:
			if got {
				return best
			}
			return exitNodeLatencyTO
		}
	}
	if got {
		return best
	}
	return exitNodeLatencyTO
}

func tryICMP(host string) (int64, error) {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return 0, err
	}
	pinger.Count = 1
	pinger.Timeout = exitNodeProbeTimeout
	pinger.SetPrivileged(true)
	if err := pinger.Run(); err != nil {
		return 0, err
	}
	stats := pinger.Statistics()
	if stats == nil || stats.PacketsRecv == 0 {
		return 0, errors.New("no icmp reply")
	}
	return positiveMS(stats.AvgRtt), nil
}

func tryTCP(host string, port int) (int64, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), exitNodeProbeTimeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return positiveMS(time.Since(start)), nil
}

func positiveMS(d time.Duration) int64 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

func publicProbeHosts(endpoints []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range endpoints {
		host := publicProbeHost(raw)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func publicProbeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "<nil>" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	return ip.String()
}

func markNearestExitNodes(nodes []models.DeviceExitNode, origin string) {
	if len(nodes) == 0 {
		return
	}
	best := -1
	bestLat := int64(1 << 30)
	for i := range nodes {
		nodes[i].Nearest = false
		if !nodes[i].Status {
			continue
		}
		lat := nodes[i].LatencyMs
		if lat > 0 && lat < exitNodeLatencyTO && lat < bestLat {
			bestLat = lat
			best = i
		}
	}
	if best >= 0 {
		nodes[best].Nearest = true
		return
	}
	olat, olon, ok := parseLatLon(origin)
	if !ok {
		return
	}
	bestDist := math.MaxFloat64
	for i, n := range nodes {
		if !n.Status {
			continue
		}
		lat, lon, ok := parseLatLon(n.Location)
		if !ok {
			continue
		}
		d := haversineKm(olat, olon, lat, lon)
		if d < bestDist {
			bestDist = d
			best = i
		}
	}
	if best >= 0 {
		nodes[best].Nearest = true
	}
}

// pickNearestAvailableExitNode returns the best exit to auto-connect.
// Always prefers the lowest measured LatencyMs among Status=true nodes.
// Nearest is only a tie-breaker. Never selects Status=false exits.
// Egress IDs in exclude are skipped.
func pickNearestAvailableExitNode(nodes []models.DeviceExitNode, exclude map[string]struct{}) (models.DeviceExitNode, bool) {
	if len(nodes) == 0 {
		return models.DeviceExitNode{}, false
	}
	excluded := func(id string) bool {
		if id == "" || len(exclude) == 0 {
			return false
		}
		_, ok := exclude[id]
		return ok
	}
	var bestUp *models.DeviceExitNode
	for i := range nodes {
		n := &nodes[i]
		if excluded(n.EgressID) || !n.Status {
			continue
		}
		if bestUp == nil || exitNodeBetterLatency(n, bestUp) {
			bestUp = n
		}
	}
	if bestUp != nil {
		return *bestUp, true
	}
	return models.DeviceExitNode{}, false
}

// exitNodeBetterLatency reports whether a is a better auto-pick than b.
// Measured RTTs win over missing/timeout; lower RTT wins; Nearest breaks ties.
func exitNodeBetterLatency(a, b *models.DeviceExitNode) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	aOK := a.LatencyMs > exitNodeLatencyNone && a.LatencyMs < exitNodeLatencyTO
	bOK := b.LatencyMs > exitNodeLatencyNone && b.LatencyMs < exitNodeLatencyTO
	switch {
	case aOK && bOK:
		if a.LatencyMs != b.LatencyMs {
			return a.LatencyMs < b.LatencyMs
		}
		return a.Nearest && !b.Nearest
	case aOK && !bOK:
		return true
	case !aOK && bOK:
		return false
	default:
		return a.Nearest && !b.Nearest
	}
}

func parseLatLon(s string) (lat, lon float64, ok bool) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0, 0, false
	}
	var err error
	lat, err = strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil {
		return 0, 0, false
	}
	lon, err = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err != nil {
		return 0, 0, false
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, false
	}
	return lat, lon, true
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	toRad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(toRad(lat1))*math.Cos(toRad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(a)))
}
