package config

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

const controlPlaneResolveTimeout = time.Second

// lookupControlPlaneIPs resolves control-plane hostnames with a context.
// Tests may replace it via SetLookupControlPlaneIPsForTest.
var lookupControlPlaneIPs = defaultLookupControlPlaneIPs

func defaultLookupControlPlaneIPs(ctx context.Context, host string) ([]net.IP, error) {
	resolver := &net.Resolver{PreferGo: true}
	return resolver.LookupIP(ctx, "ip", host)
}

// SetLookupControlPlaneIPsForTest replaces the resolver used by RefreshControlPlaneEndpoints.
// Pass nil to restore the default bounded resolver.
func SetLookupControlPlaneIPsForTest(fn func(host string) ([]net.IP, error)) {
	if fn == nil {
		lookupControlPlaneIPs = defaultLookupControlPlaneIPs
		return
	}
	lookupControlPlaneIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		done := make(chan struct{})
		var ips []net.IP
		var err error
		go func() {
			ips, err = fn(host)
			close(done)
		}()
		select {
		case <-done:
			return ips, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

var (
	controlPlaneMu     sync.RWMutex
	controlPlaneByHost = map[string][]net.IP{} // hostname (no port) → IPs
)

// ControlPlaneHostnames returns unique API/broker hostnames for the current server.
func ControlPlaneHostnames() []string {
	server := GetServer(CurrServer)
	if server == nil {
		return nil
	}
	hosts := []string{
		NormalizeServerHost(server.API),
		NormalizeServerHost(server.APIHost),
		NormalizeServerHost(server.Broker),
	}
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// IsControlPlaneHostname reports whether name (DNS question form OK) is the
// current server's API or broker host. Used to scope public-DNS fallback.
func IsControlPlaneHostname(name string) bool {
	host := normalizeDNSHostname(name)
	if host == "" {
		return false
	}
	for _, h := range ControlPlaneHostnames() {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// ControlPlanePinIPs returns all cached control-plane IPs for underlay pinning.
func ControlPlanePinIPs() []net.IP {
	controlPlaneMu.RLock()
	defer controlPlaneMu.RUnlock()
	seen := make(map[string]struct{})
	var out []net.IP
	for _, ips := range controlPlaneByHost {
		for _, ip := range ips {
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, append(net.IP(nil), ip...))
		}
	}
	return out
}

// ControlPlaneIPsForHost returns cached IPs for a hostname (DNS question OK).
func ControlPlaneIPsForHost(name string) []net.IP {
	host := normalizeDNSHostname(name)
	if host == "" {
		return nil
	}
	controlPlaneMu.RLock()
	defer controlPlaneMu.RUnlock()
	ips := controlPlaneByHost[strings.ToLower(host)]
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out
}

// RefreshControlPlaneEndpoints resolves API/broker IPs, updates the in-memory
// map, and persists them on the server config when they change. On resolve
// failure, keeps prior memory/persisted values. Returns true if servers.json
// should be written.
func RefreshControlPlaneEndpoints(server *Server) (changed bool) {
	if server == nil {
		server = GetServer(CurrServer)
	}
	if server == nil {
		return false
	}

	apiHost := NormalizeServerHost(server.API)
	if apiHost == "" {
		apiHost = NormalizeServerHost(server.APIHost)
	}
	brokerHost := NormalizeServerHost(server.Broker)

	apiIPs := resolveControlPlaneHost(apiHost)
	brokerIPs := resolveControlPlaneHost(brokerHost)

	serverMutex.Lock()
	defer serverMutex.Unlock()

	key := server.Name
	if key == "" {
		key = CurrServer
	}
	s, ok := Servers[key]
	if !ok {
		s = *server
	}

	byHost := make(map[string][]net.IP)
	if len(apiIPs) > 0 {
		addrs := ipsToStrings(apiIPs)
		if !stringSlicesEqual(s.CachedAPIAddrs, addrs) {
			s.CachedAPIAddrs = addrs
			changed = true
		}
		setControlPlaneHostMap(byHost, apiHost, apiIPs)
		if h := NormalizeServerHost(s.APIHost); h != "" {
			setControlPlaneHostMap(byHost, h, apiIPs)
		}
	} else if len(s.CachedAPIAddrs) > 0 {
		setControlPlaneHostMap(byHost, apiHost, parseIPList(s.CachedAPIAddrs))
		if h := NormalizeServerHost(s.APIHost); h != "" {
			setControlPlaneHostMap(byHost, h, parseIPList(s.CachedAPIAddrs))
		}
	}
	if len(brokerIPs) > 0 {
		addrs := ipsToStrings(brokerIPs)
		if !stringSlicesEqual(s.CachedBrokerAddrs, addrs) {
			s.CachedBrokerAddrs = addrs
			changed = true
		}
		setControlPlaneHostMap(byHost, brokerHost, brokerIPs)
	} else if len(s.CachedBrokerAddrs) > 0 {
		setControlPlaneHostMap(byHost, brokerHost, parseIPList(s.CachedBrokerAddrs))
	}

	Servers[key] = s
	*server = s
	replaceControlPlaneByHost(byHost)

	if changed {
		slog.Info("refreshed control-plane endpoint IPs",
			"server", key,
			"api_host", apiHost,
			"api_addrs", s.CachedAPIAddrs,
			"broker_host", brokerHost,
			"broker_addrs", s.CachedBrokerAddrs,
		)
	}
	return changed
}

// SeedControlPlaneEndpointsFromServers loads persisted API/broker IPs into memory.
func SeedControlPlaneEndpointsFromServers() {
	serverMutex.RLock()
	defer serverMutex.RUnlock()
	byHost := make(map[string][]net.IP)
	for _, s := range Servers {
		apiHost := NormalizeServerHost(s.API)
		if apiHost == "" {
			apiHost = NormalizeServerHost(s.APIHost)
		}
		if len(s.CachedAPIAddrs) > 0 {
			setControlPlaneHostMap(byHost, apiHost, parseIPList(s.CachedAPIAddrs))
			if h := NormalizeServerHost(s.APIHost); h != "" {
				setControlPlaneHostMap(byHost, h, parseIPList(s.CachedAPIAddrs))
			}
		}
		if len(s.CachedBrokerAddrs) > 0 {
			setControlPlaneHostMap(byHost, NormalizeServerHost(s.Broker), parseIPList(s.CachedBrokerAddrs))
		}
	}
	replaceControlPlaneByHost(byHost)
}

func resolveControlPlaneHost(host string) []net.IP {
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if isCacheableEndpointIP(ip) {
			return []net.IP{append(net.IP(nil), ip...)}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlPlaneResolveTimeout)
	defer cancel()
	ips, err := lookupControlPlaneIPs(ctx, host)
	if err != nil {
		slog.Debug("control-plane resolve failed", "host", host, "error", err)
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if !isCacheableEndpointIP(ip) {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}

func isCacheableEndpointIP(ip net.IP) bool {
	if len(ip) == 0 || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	s := ip.String()
	return s != "" && s != "<nil>"
}

func normalizeDNSHostname(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	return NormalizeServerHost(name)
}

func setControlPlaneHostMap(dst map[string][]net.IP, host string, ips []net.IP) {
	host = strings.ToLower(NormalizeServerHost(host))
	if host == "" || len(ips) == 0 {
		return
	}
	cp := make([]net.IP, len(ips))
	copy(cp, ips)
	dst[host] = cp
}

func replaceControlPlaneByHost(byHost map[string][]net.IP) {
	controlPlaneMu.Lock()
	defer controlPlaneMu.Unlock()
	controlPlaneByHost = byHost
}

func parseIPList(addrs []string) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if !isCacheableEndpointIP(ip) {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if len(ip) == 0 {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
