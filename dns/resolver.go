package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/dns/querycache"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

const (
	ttlTimeout = 3600
)

var dnsMapMutex sync.RWMutex // used to mutex functions of the DNS

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

// ServeDNS handles a DNS request
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.RecursionDesired = true
	reply.Rcode = dns.RcodeSuccess
	logger.Log(4, fmt.Sprintf("resolving dns query %s", r.Question[0].Name))
	// IPv4-only exit diverts ::/0 to utun without peer ::/0 AllowedIPs, so AAAA
	// answers make browsers Happy-Eyeballs-stall on a blackhole. Refuse AAAA up
	// front and strip AAAA from mixed answers so pages use IPv4 via the exit.
	if ipv4OnlyInternetExit() && r.Question[0].Qtype == dns.TypeAAAA {
		reply.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(reply)
		return
	}
	if igwDNS := internetGwDNSServer(); igwDNS != "" {
		qName := r.Question[0].Name
		logger.Log(4, fmt.Sprintf(
			"connected to gw, forwarding dns query %s to gw %s",
			qName,
			igwDNS,
		))

		resp, err := exchangeDNSQueryWithPool(r, igwDNS)
		if err != nil {
			logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with gw %s: %v", qName, igwDNS, err))
		} else if resp != nil {
			// Preserve prior IGW DNS behavior: use whatever the exit resolver returned.
			logger.Log(4, fmt.Sprintf("resolved dns query %s with gw %s: %v", qName, igwDNS, resp.Answer))
			reply.Authoritative = resp.Authoritative
			reply.Answer = append(reply.Answer, resp.Answer...)
			if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 {
				reply.Rcode = resp.Rcode
			}
		}

		// Control-plane only: if exit DNS yields no answers, use pin-cache A/AAAA
		// or public resolvers for API/broker hostnames. Other names stay on exit DNS.
		if len(reply.Answer) == 0 && config.IsControlPlaneHostname(qName) {
			if local := controlPlaneAnswers(r); len(local) > 0 {
				logger.Log(4, fmt.Sprintf("resolved control-plane %s from underlay pin cache", qName))
				reply.Rcode = dns.RcodeSuccess
				reply.Answer = append(reply.Answer, local...)
				reply.Authoritative = true
			} else if publicResp, pubErr := resolveViaPublicDNSServers(r); pubErr != nil {
				logger.Log(4, fmt.Sprintf("control-plane public DNS fallback failed for %s: %v", qName, pubErr))
			} else if publicResp != nil && len(publicResp.Answer) > 0 {
				logger.Log(4, fmt.Sprintf("resolved control-plane %s via public DNS fallback", qName))
				reply.Rcode = dns.RcodeSuccess
				reply.Authoritative = publicResp.Authoritative
				reply.Answer = append(reply.Answer, publicResp.Answer...)
			}
		}
	} else {
		query := canonicalizeDomainForMatching(r.Question[0].Name)
		currServer := config.GetServer(config.CurrServer)
		if currServer == nil {
			reply.Rcode = dns.RcodeServerFailure
		} else {
			if MatchesEgressDomain(r.Question[0].Name) {
				logger.Log(4, fmt.Sprintf("resolving egress domain %s via egress DNS", r.Question[0].Name))
				publicResp, err := ResolveEgressQuery(r)
				if err == nil && publicResp != nil && len(publicResp.Answer) > 0 {
					reply.Answer = append(reply.Answer, publicResp.Answer...)
					reply.Authoritative = publicResp.Authoritative
					go recordDNSAnswers(reply.Answer)
					_ = w.WriteMsg(reply)
					return
				}
				if err != nil {
					logger.Log(4, fmt.Sprintf("egress domain public DNS failed for %s: %v", r.Question[0].Name, err))
				}
			}

			// query matches default domain, resolve with local records
			logger.Log(4, fmt.Sprintf("resolving dns query %s with local records", r.Question[0].Name))

			resp, err := GetDNSResolverInstance().Lookup(r)
			if err != nil {
				logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with local records: %v", r.Question[0].Name, err))
			} else {
				logger.Log(4, fmt.Sprintf("resolved dns query %s with local records: %v", r.Question[0].Name, resp))
				reply.Authoritative = true
				reply.Answer = append(reply.Answer, resp)
			}
			if len(reply.Answer) == 0 {
				bestMatchNameservers := findBestMatch(query, currServer.DnsNameservers)
				for _, nameserver := range bestMatchNameservers {
					if nameserver.IsFallback {
						continue
					}
					var queryResolved bool
					for _, ns := range nameserver.IPs {
						logger.Log(4, fmt.Sprintf("found best match %s, forwarding dns query %s to nameserver %s", nameserver.MatchDomain, r.Question[0].Name, ns))

						resp, err := exchangeDNSQueryWithPool(r, ns)
						if err != nil || resp == nil || len(resp.Answer) == 0 {
							if err != nil {
								logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: %v", r.Question[0].Name, ns, err))
							} else {
								logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: no answer", r.Question[0].Name, ns))
							}
							continue
						}

						if resp.Rcode != dns.RcodeSuccess {
							logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with nameserver %s: rcode %d", r.Question[0].Name, ns, resp.Rcode))
							continue
						}

						if len(resp.Answer) > 0 {
							logger.Log(4, fmt.Sprintf("resolved dns query %s with nameserver %s: %v", r.Question[0].Name, ns, resp.Answer))
							reply.Answer = append(reply.Answer, resp.Answer...)
							reply.Authoritative = resp.Authoritative
							queryResolved = true
							break
						}
					}
					if queryResolved {
						break
					}
				}

				if len(reply.Answer) == 0 {
					logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with configured nameservers, falling back to fallback nameservers", r.Question[0].Name))

					for _, nameserver := range bestMatchNameservers {
						if nameserver.IsFallback {
							var queryResolved bool
							for _, ns := range nameserver.IPs {
								logger.Log(4, fmt.Sprintf("forwarding dns query %s to fallback nameserver %s", r.Question[0].Name, ns))

								resp, err := exchangeDNSQueryWithPool(r, ns)
								if err != nil || resp == nil || len(resp.Answer) == 0 {
									if err != nil {
										logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: %v", r.Question[0].Name, ns, err))
									} else {
										logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: no answer", r.Question[0].Name, ns))
									}
									continue
								}

								if resp.Rcode != dns.RcodeSuccess {
									logger.Log(4, fmt.Sprintf("failed to resolve dns query %s with fallback nameserver %s: rcode %d", r.Question[0].Name, ns, resp.Rcode))
									continue
								}

								if len(resp.Answer) > 0 {
									logger.Log(4, fmt.Sprintf("resolved dns query %s with fallback nameserver %s: %v", r.Question[0].Name, ns, resp.Answer))
									reply.Answer = append(reply.Answer, resp.Answer...)
									reply.Authoritative = resp.Authoritative
									queryResolved = true
									break
								}
							}
							if queryResolved {
								break
							}
						}
					}
				}
			}
		}
	}

	if ipv4OnlyInternetExit() {
		reply.Answer = stripAAAARecords(reply.Answer)
	}
	go recordDNSAnswers(reply.Answer)
	_ = w.WriteMsg(reply)
}

// ipv4OnlyInternetExit reports whether an IPv4 exit is active with no IPv6
// nexthop. In that mode host IPv6 is diverted onto the WireGuard iface and
// blackholed (leak prevention), so AAAA must not be handed to browsers.
func ipv4OnlyInternetExit() bool {
	nc := config.Netclient()
	if nc == nil || len(nc.CurrGwNmIP) == 0 || nc.CurrGwNmIP.To4() == nil {
		return false
	}
	return len(nc.CurrGwNmIP6) == 0
}

func stripAAAARecords(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr != nil && rr.Header().Rrtype == dns.TypeAAAA {
			continue
		}
		out = append(out, rr)
	}
	return out
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
	dnsMapMutex.RLock()
	defer dnsMapMutex.RUnlock()
	q := m.Question[0]
	r, ok := d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), q.Qtype)]
	if !ok {
		switch q.Qtype {
		case dns.TypeA:
			_, ok = d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), dns.TypeAAAA)]
			if ok {
				// aware but no ipv6 address
				return nil, ErrNoQTypeRecord
			}
		case dns.TypeAAAA:
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

// internetGwDNSServer returns the overlay nexthop used as the exit DNS
// forwarder when an internet gateway route is active.
func internetGwDNSServer() string {
	nc := config.Netclient()
	if nc == nil {
		return ""
	}
	if len(nc.CurrGwNmIP) > 0 {
		return nc.CurrGwNmIP.String()
	}
	if len(nc.CurrGwNmIP6) > 0 {
		return nc.CurrGwNmIP6.String()
	}
	return ""
}

// controlPlaneAnswers builds A/AAAA RRs from cached control-plane underlay IPs.
func controlPlaneAnswers(r *dns.Msg) []dns.RR {
	if r == nil || len(r.Question) == 0 {
		return nil
	}
	q := r.Question[0]
	ips := config.ControlPlaneIPsForHost(q.Name)
	if len(ips) == 0 {
		return nil
	}
	var out []dns.RR
	for _, ip := range ips {
		switch q.Qtype {
		case dns.TypeA:
			if v4 := ip.To4(); v4 != nil {
				out = append(out, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   v4,
				})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil && ip.To16() != nil {
				out = append(out, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip,
				})
			}
		case dns.TypeANY:
			if v4 := ip.To4(); v4 != nil {
				out = append(out, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   v4,
				})
			} else if ip.To16() != nil {
				out = append(out, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip,
				})
			}
		}
	}
	return out
}

// resolveViaPublicDNSServers forwards a query to well-known public resolvers.
// Only used for scoped control-plane fallback.
func resolveViaPublicDNSServers(r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) == 0 {
		return nil, errors.New("empty DNS question")
	}
	var lastErr error
	for _, server := range egressPublicDNSServers {
		resp, err := exchangeDNSQueryWithPool(r, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return resp, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no answer from public DNS for %s", r.Question[0].Name)
}

func exchangeDNSQueryWithPool(r *dns.Msg, ns string) (*dns.Msg, error) {
	// Normalize IPv6 if needed
	if strings.Contains(ns, ":") && !strings.HasPrefix(ns, "[") {
		ns = "[" + ns + "]"
	}
	serverAddr := ns + ":53"

	conn, err := dnsUDPConnPool.get(serverAddr)
	if err != nil {
		return nil, err
	}

	dnsConn := &dns.Conn{
		Conn:    conn,
		UDPSize: dns.DefaultMsgSize,
	}

	client := &dns.Client{Net: "udp", Timeout: time.Second * 3}
	resp, _, err := client.ExchangeWithConn(r, dnsConn)
	if err != nil {
		// A socket that just failed is not worth recycling: the netmaker iface is
		// torn down and rebuilt on mode flips, which leaves sockets bound to a
		// source address that no longer exists. Keeping them in the pool makes
		// every later query through this server fail too.
		_ = conn.Close()
		return nil, err
	}

	dnsUDPConnPool.put(serverAddr, conn)
	return resp, nil
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

func recordDNSAnswers(answers []dns.RR) {
	now := time.Now()
	for _, rr := range answers {
		switch r := rr.(type) {
		case *dns.A:
			querycache.GetManager().Record(r.A.String(), r.Hdr.Name, now)
		case *dns.AAAA:
			querycache.GetManager().Record(r.AAAA.String(), r.Hdr.Name, now)
		}
	}
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
