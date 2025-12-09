package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

const (
	ttlTimeout = 3600
)

var dnsMapMutex = sync.Mutex{} // used to mutex functions of the DNS

var (
	ErrNXDomain      = errors.New("non existent domain")
	ErrNoQTypeRecord = errors.New("domain exists but no record matching the question type")
	dnsUDPConnPool   = newUDPConnPool()
)

type DNSResolver struct {
	DnsEntriesCacheStore map[string]dns.RR
	DnsEntriesCacheMap   map[string][]dnsRecord
}

var DnsResolver *DNSResolver

func init() {
	DnsResolver = &DNSResolver{
		DnsEntriesCacheStore: make(map[string]dns.RR),
		DnsEntriesCacheMap:   make(map[string][]dnsRecord),
	}
}

// GetInstance
func GetDNSResolverInstance() *DNSResolver {
	return DnsResolver
}

func isInternetGW() bool {
	// TODO: let netclient know if it's an igw.
	return true
}

// ServeDNS handles a DNS request
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.RecursionDesired = true
	reply.Rcode = dns.RcodeSuccess

	logger.Log(4, fmt.Sprintf("resolving dns query %s", r.Question[0].Name))

	if config.Netclient().CurrGwNmIP != nil {
		logger.Log(4, fmt.Sprintf(
			"connected to gw, forwarding dns query %s to gw %s",
			r.Question[0].Name,
			config.Netclient().CurrGwNmIP.String()),
		)

		resp, err := exchangeDNSQueryWithPool(r, config.Netclient().CurrGwNmIP.String())
		if err == nil {
			reply.Answer = append(reply.Answer, resp.Answer...)
		}
	} else {
		query := canonicalizeDomainForMatching(r.Question[0].Name)

		bestMatchNameservers := findBestMatch(query, config.GetServer(config.CurrServer).DnsNameservers)

		// if the best match nameserver is not a match-all nameserver, forward the query to it.
		if len(bestMatchNameservers) > 0 && bestMatchNameservers[0].MatchDomain != "." {
			for _, nameserver := range bestMatchNameservers {
				for _, ns := range nameserver.IPs {
					logger.Log(4, fmt.Sprintf("found best match %s, forwarding dns query %s to nameserver %s", nameserver.MatchDomain, r.Question[0].Name, ns))

					resp, err := exchangeDNSQueryWithPool(r, ns)
					if err != nil || resp == nil || len(resp.Answer) == 0 {
						continue
					}

					if resp.Rcode != dns.RcodeSuccess {
						continue
					}

					if len(resp.Answer) > 0 {
						reply.Answer = append(reply.Answer, resp.Answer...)
						break
					}
				}
			}
		}

		if len(reply.Answer) == 0 {
			// if the best match nameserver couldn't resolve the query, try to resolve it with local records.
			logger.Log(4, fmt.Sprintf("resolving dns query %s with local records", r.Question[0].Name))

			resp, err := GetDNSResolverInstance().Lookup(r)
			if err == nil {
				reply.Authoritative = true
				reply.Answer = append(reply.Answer, resp)
			}
		}

		if len(reply.Answer) == 0 {
			// if the best match nameserver is a match-all nameserver, we can now forward the query to it.
			if len(bestMatchNameservers) > 0 && bestMatchNameservers[0].MatchDomain == "." {
				for _, nameserver := range bestMatchNameservers {
					for _, ns := range nameserver.IPs {
						logger.Log(4, fmt.Sprintf("forwarding dns query %s to match-all nameserver %s", r.Question[0].Name, ns))

						resp, err := exchangeDNSQueryWithPool(r, ns)
						if err != nil || resp == nil || len(resp.Answer) == 0 {
							continue
						}

						if resp.Rcode != dns.RcodeSuccess {
							continue
						}

						if len(resp.Answer) > 0 {
							reply.Answer = append(reply.Answer, resp.Answer...)
							break
						}
					}
				}
			}
		}

		if len(reply.Answer) == 0 {
			// if nothing worked, fallback to the old system.
			logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with new system, falling back to old system", r.Question[0].Name))

			reply = &dns.Msg{}
			reply.SetReply(r)
			reply.RecursionAvailable = true
			reply.RecursionDesired = true
			reply.Rcode = dns.RcodeSuccess

			fallbackNameservers := config.Netclient().NameServers
			server := config.GetServer(config.CurrServer)
			if server != nil {
				fallbackNameservers = append(fallbackNameservers, server.NameServers...)
			}

			if isInternetGW() {
				fallbackNameservers = append(fallbackNameservers, []string{
					"8.8.8.8",
					"8.8.4.4",
					"2001:4860:4860::8888",
					"2001:4860:4860::8844",
				}...)
			}

			for _, ns := range fallbackNameservers {
				logger.Log(4, fmt.Sprintf("forwarding dns query %s to fallback nameserver %s", r.Question[0].Name, ns))

				resp, err := exchangeDNSQueryWithPool(r, ns)
				if err != nil || resp == nil || len(resp.Answer) == 0 {
					continue
				}

				if resp.Rcode != dns.RcodeSuccess {
					continue
				}

				if len(resp.Answer) > 0 {
					reply.Answer = append(reply.Answer, resp.Answer...)
					break
				}
			}
		}
	}

	_ = w.WriteMsg(reply)
}

func FindDnsAns(domain string) []net.IP {
	nslist := []string{}
	if config.Netclient().CurrGwNmIP != nil {
		nslist = append(nslist, config.Netclient().CurrGwNmIP.String())
	} else {
		query := canonicalizeDomainForMatching(domain)
		matchNsList := findBestMatch(query, config.GetServer(config.CurrServer).DnsNameservers)
		for i := len(matchNsList) - 1; i >= 0; i-- {
			nslist = append(nslist, matchNsList[i].IPs...)
		}
	}
	nslist = append(nslist, "8.8.8.8")
	nslist = append(nslist, "8.8.4.4")
	nslist = append(nslist, "1.1.1.1")
	nslist = append(nslist, "2001:4860:4860::8888")
	nslist = append(nslist, "2001:4860:4860::8844")
	server := config.GetServer(config.CurrServer)
	if server != nil {
		nslist = append(nslist, server.NameServers...)
	}
	for _, v := range nslist {
		if strings.Contains(v, ":") {
			v = "[" + v + "]"
		}
		if ansIps, err := internalLookupA(domain, v); err == nil && len(ansIps) > 0 {
			return ansIps
		}
	}
	return []net.IP{}
}

// Build a query and send via your pool/upstream.
func internalLookupA(name, ns string) ([]net.IP, error) {
	r := new(dns.Msg)
	r.Id = dns.Id()
	r.RecursionDesired = true
	r.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r.SetEdns0(1232, true)

	resp, err := exchangeDNSQueryWithPool(r, ns) // e.g., "1.1.1.1"
	if err != nil || resp == nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	return ips, nil
}

// Register A record
func (d *DNSResolver) RegisterA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttlTimeout}
	r.A = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	slog.Debug("registering A record successfully", "Info", d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)])

	return nil
}

// Register AAAA record
func (d *DNSResolver) RegisterAAAA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlTimeout}
	r.AAAA = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	slog.Debug("registering AAAA record successfully", "Info", d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)])

	return nil
}

// Lookup DNS entry in local directory
func (d *DNSResolver) Lookup(m *dns.Msg) (dns.RR, error) {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()
	q := m.Question[0]
	r, ok := d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), q.Qtype)]
	if !ok {
		if q.Qtype == dns.TypeA {
			_, ok = d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), dns.TypeAAAA)]
			if ok {
				// aware but no ipv6 address
				return nil, ErrNoQTypeRecord
			}
		} else if q.Qtype == dns.TypeAAAA {
			_, ok = d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), dns.TypeA)]
			if ok {
				// aware but no ipv4 address
				return nil, ErrNoQTypeRecord
			}
		}

		return nil, ErrNXDomain
	}

	return r, nil
}

func exchangeDNSQueryWithPool(r *dns.Msg, ns string) (*dns.Msg, error) {
	// Normalize IPv6 if needed
	if strings.Contains(ns, ":") && !strings.HasPrefix(ns, "[") {
		ns = "[" + ns + "]"
	}
	serverAddr := ns + ":53"

	// Try up to 2 times: once with pooled connection, once with fresh connection
	maxRetries := 2
	var resp *dns.Msg
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, connErr := dnsUDPConnPool.get(serverAddr)
		if connErr != nil {
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("failed to get UDP connection after %d attempts: %w", maxRetries, connErr)
			}
			continue
		}

		// Log the source IP that will be used for this query
		// This helps debug routing issues with stub resolvers
		if localAddr := conn.LocalAddr(); localAddr != nil {
			logger.Log(4, fmt.Sprintf("DNS query to %s using source IP %s", serverAddr, localAddr.String()))
		}

		dnsConn := &dns.Conn{
			Conn:    conn,
			UDPSize: dns.DefaultMsgSize,
		}

		client := &dns.Client{Net: "udp", Timeout: time.Second * 3}
		resp, _, err = client.ExchangeWithConn(r, dnsConn)

		if err == nil && resp != nil {
			// Success - put the connection back in the pool for reuse
			dnsUDPConnPool.put(serverAddr, conn)
			return resp, nil
		}

		// Connection failed - close it and don't put it back in the pool
		// This ensures we get a fresh connection on the next attempt
		// This is especially important with stub resolvers where routing can be complex
		dnsUDPConnPool.closeConnection(conn)

		// If this isn't the last attempt, try again with a fresh connection
		if attempt < maxRetries-1 {
			continue
		}
	}

	return resp, err
}

func findBestMatch(domain string, nameservers []models.Nameserver) []models.Nameserver {
	var bestMatch []models.Nameserver
	bestScore := -1

	for _, nameserver := range nameservers {
		matchDomain := canonicalizeDomainForMatching(nameserver.MatchDomain)

		if strings.HasSuffix(domain, matchDomain) {
			currScore := strings.Count(matchDomain, ".")

			if currScore > bestScore {
				bestMatch = []models.Nameserver{nameserver}
				bestScore = currScore
			} else if currScore == bestScore {
				bestMatch = append(bestMatch, nameserver)
			}
		}
	}

	return bestMatch
}

func canonicalizeDomainForMatching(domain string) string {
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	return domain
}
