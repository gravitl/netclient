package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

// Public resolvers used for egress domain resolution (routes and client DNS).
var egressPublicDNSServers = []string{
	"8.8.8.8",
	"1.1.1.1",
}

const egressPublicDNSLookupTimeout = 5 * time.Second
const egressMaxResolvedIPs = 4

var (
	egressDomainPatterns      []string
	egressDomainPatternsMutex sync.RWMutex
)

// SyncEgressDomainPatterns updates the list of domain patterns answered via public DNS.
func SyncEgressDomainPatterns(domains []models.EgressDomain) {
	patterns := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		pattern := strings.TrimSpace(strings.ToLower(d.Domain))
		if pattern == "" {
			continue
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}

	egressDomainPatternsMutex.Lock()
	egressDomainPatterns = patterns
	egressDomainPatternsMutex.Unlock()

	slog.Debug("synced egress domain DNS patterns", "count", len(patterns))
}

// ClearEgressDomainPatterns removes egress-domain public DNS overrides.
func ClearEgressDomainPatterns() {
	egressDomainPatternsMutex.Lock()
	egressDomainPatterns = nil
	egressDomainPatternsMutex.Unlock()
}

// MatchesEgressDomain reports whether name should be resolved via public DNS instead of local Netmaker records.
func MatchesEgressDomain(name string) bool {
	query := normalizeDomainName(name)
	if query == "" {
		return false
	}

	egressDomainPatternsMutex.RLock()
	patterns := egressDomainPatterns
	egressDomainPatternsMutex.RUnlock()

	for _, pattern := range patterns {
		if domainMatchesPattern(query, pattern) {
			return true
		}
	}
	return false
}

func domainMatchesPattern(query, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		if base == "" || strings.Contains(base, "*") {
			return false
		}
		return query == base || strings.HasSuffix(query, "."+base)
	}
	return query == pattern || strings.HasSuffix(query, "."+pattern)
}

func normalizeDomainName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.Trim(name, ".")
	return name
}

// NormalizeEgressLookupDomain strips a leading "*." used in egress domain policy names.
func NormalizeEgressLookupDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", errEmptyEgressDomain
	}
	if strings.HasPrefix(domain, "*.") {
		lookupDomain := strings.TrimPrefix(domain, "*.")
		if lookupDomain == "" || strings.Contains(lookupDomain, "*") {
			return "", errInvalidEgressWildcard
		}
		return lookupDomain, nil
	}
	return domain, nil
}

var (
	errEmptyEgressDomain     = &egressDomainError{"domain cannot be empty"}
	errInvalidEgressWildcard = &egressDomainError{"invalid wildcard domain"}
)

type egressDomainError struct {
	msg string
}

func (e *egressDomainError) Error() string { return e.msg }

func egressResolutionServersForDomain(name string) []string {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return append([]string(nil), egressPublicDNSServers...)
	}
	return egressResolutionServersFrom(name, server.DnsNameservers)
}

func egressResolutionServersFrom(domain string, nameservers []models.Nameserver) []string {
	if len(nameservers) == 0 {
		return append([]string(nil), egressPublicDNSServers...)
	}

	query := canonicalizeDomainForMatching(domain)
	bestMatch := findBestMatch(query, nameservers)
	if len(bestMatch) == 0 {
		return append([]string(nil), egressPublicDNSServers...)
	}

	seen := make(map[string]struct{})
	servers := collectNameserverIPs(nil, bestMatch, false, seen)
	servers = collectNameserverIPs(servers, bestMatch, true, seen)
	if len(servers) == 0 {
		return append([]string(nil), egressPublicDNSServers...)
	}
	return servers
}

func collectNameserverIPs(servers []string, nameservers []models.Nameserver, fallbackOnly bool, seen map[string]struct{}) []string {
	for _, ns := range nameservers {
		if ns.IsFallback != fallbackOnly {
			continue
		}
		for _, ip := range ns.IPs {
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			servers = append(servers, ip)
		}
	}
	return servers
}

func formatDNSServerAddr(ip string) string {
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]:53"
	}
	return ip + ":53"
}

func limitEgressIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return ips
	}

	seen := make(map[string]struct{}, len(ips))
	limited := make([]net.IP, 0, egressMaxResolvedIPs)
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		limited = append(limited, ip)
		if len(limited) >= egressMaxResolvedIPs {
			break
		}
	}
	return limited
}

func limitEgressDNSAnswers(answers []dns.RR) []dns.RR {
	if len(answers) == 0 {
		return answers
	}

	limited := make([]dns.RR, 0, len(answers))
	seen := make(map[string]struct{})
	ipCount := 0
	for _, rr := range answers {
		switch r := rr.(type) {
		case *dns.A:
			if ipCount >= egressMaxResolvedIPs {
				continue
			}
			key := r.A.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ipCount++
			limited = append(limited, rr)
		case *dns.AAAA:
			if ipCount >= egressMaxResolvedIPs {
				continue
			}
			key := r.AAAA.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ipCount++
			limited = append(limited, rr)
		default:
			limited = append(limited, rr)
		}
	}
	return limited
}

// LookupHostViaPublicDNS resolves a hostname using configured egress DNS nameservers.
// It falls back to public resolvers (8.8.8.8, then 1.1.1.1) when no nameserver matches.
// It stops at the first resolver that returns addresses.
func LookupHostViaPublicDNS(name string) ([]net.IP, error) {
	name = normalizeDomainName(name)
	if name == "" {
		return nil, errEmptyEgressDomain
	}

	var lastErr error

	for _, server := range egressResolutionServersForDomain(name) {
		serverAddr := formatDNSServerAddr(server)
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: egressPublicDNSLookupTimeout}
				return dialer.DialContext(ctx, "udp", serverAddr)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), egressPublicDNSLookupTimeout)
		addrs, err := resolver.LookupIPAddr(ctx, name)
		cancel()
		if err != nil {
			lastErr = err
			slog.Debug("egress DNS lookup failed", "domain", name, "server", server, "error", err)
			continue
		}

		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP != nil {
				ips = append(ips, addr.IP)
			}
		}
		if len(ips) > 0 {
			ips = limitEgressIPs(ips)
			slog.Debug("egress DNS lookup succeeded", "domain", name, "server", server, "count", len(ips))
			return ips, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &egressDomainError{"no IP addresses returned for " + name}
}

// ResolveEgressQuery forwards a DNS query to egress nameservers when the name is an egress domain.
func ResolveEgressQuery(r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) == 0 {
		return nil, &egressDomainError{"empty DNS question"}
	}

	q := r.Question[0]
	if !MatchesEgressDomain(q.Name) {
		return nil, nil
	}

	var lastErr error
	for _, server := range egressResolutionServersForDomain(normalizeDomainName(q.Name)) {
		resp, err := exchangeDNSQueryWithPool(r, server)
		if err != nil {
			lastErr = err
			slog.Debug("egress domain DNS forward failed", "name", q.Name, "server", server, "error", err)
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			resp.Answer = limitEgressDNSAnswers(resp.Answer)
			if len(resp.Answer) > 0 {
				return resp, nil
			}
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &egressDomainError{"no answer from egress DNS for " + q.Name}
}
