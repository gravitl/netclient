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
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

const (
	exitNodeProbeTimeout = time.Second
	exitNodeLatencyNone  = int64(0)
	exitNodeLatencyTO    = int64(999)
)

func attachExitNodeLatencies(network string, nodes []models.DeviceExitNode) {
	if len(nodes) == 0 {
		return
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
	origin := ""
	if nc := config.Netclient(); nc != nil {
		origin = nc.Location
	}
	markNearestExitNodes(nodes, origin)
	slog.Info("exit node latencies attached",
		"network", network,
		"nodes", len(nodes),
		"resolved_endpoints", resolved,
	)
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
