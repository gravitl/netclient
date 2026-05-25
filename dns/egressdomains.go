package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

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

// LookupHostViaPublicDNS resolves a hostname using public resolvers (8.8.8.8, then 1.1.1.1).
// It stops at the first resolver that returns addresses.
func LookupHostViaPublicDNS(name string) ([]net.IP, error) {
	name = normalizeDomainName(name)
	if name == "" {
		return nil, errEmptyEgressDomain
	}

	var lastErr error

	for _, server := range egressPublicDNSServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: egressPublicDNSLookupTimeout}
				return dialer.DialContext(ctx, "udp", server+":53")
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), egressPublicDNSLookupTimeout)
		addrs, err := resolver.LookupIPAddr(ctx, name)
		cancel()
		if err != nil {
			lastErr = err
			slog.Debug("egress public DNS lookup failed", "domain", name, "server", server, "error", err)
			continue
		}

		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP != nil {
				ips = append(ips, addr.IP)
			}
		}
		if len(ips) > 0 {
			slog.Debug("egress public DNS lookup succeeded", "domain", name, "server", server, "count", len(ips))
			return ips, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &egressDomainError{"no IP addresses returned for " + name}
}

// ResolveEgressQuery forwards a DNS query to public resolvers when the name is an egress domain.
func ResolveEgressQuery(r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) == 0 {
		return nil, &egressDomainError{"empty DNS question"}
	}

	q := r.Question[0]
	if !MatchesEgressDomain(q.Name) {
		return nil, nil
	}

	var lastErr error
	for _, server := range egressPublicDNSServers {
		resp, err := exchangeDNSQueryWithPool(r, server)
		if err != nil {
			lastErr = err
			slog.Debug("egress domain DNS forward failed", "name", q.Name, "server", server, "error", err)
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return resp, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &egressDomainError{"no answer from public DNS for " + q.Name}
}
