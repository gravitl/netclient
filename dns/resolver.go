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
	for _, v := range config.GetNodes() {
		if v.IsIngressGateway {
			return true
		}
	}

	return false
}

// ServeDNS handles a DNS request
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.RecursionDesired = true
	reply.Rcode = dns.RcodeSuccess

	domain := strings.TrimSuffix(r.Question[0].Name, ".")

	logger.Log(4, fmt.Sprintf("handling dns request for domain %s", domain))

	if config.Netclient().CurrGwNmIP != nil {
		resp, err := exchangeDNSQueryWithPool(r, config.Netclient().CurrGwNmIP.String())
		if err != nil {
			if errors.Is(err, ErrNXDomain) {
				reply.Rcode = dns.RcodeNameError
			} else {
				reply.Rcode = dns.RcodeServerFailure
			}
		} else {
			reply.Answer = append(reply.Answer, resp.Answer...)
		}
	} else {
		var foundDomainMatch bool
		for _, nameserver := range config.GetServer(config.CurrServer).DnsNameservers {
			matchDomain := nameserver.MatchDomain
			if !strings.HasPrefix(nameserver.MatchDomain, ".") {
				matchDomain = "." + nameserver.MatchDomain
			}

			if strings.HasSuffix(domain, matchDomain) {
				foundDomainMatch = true

				for _, ns := range nameserver.IPs {
					logger.Log(4, fmt.Sprintf("forwarding request to nameserver %s for domain %s", ns, matchDomain))
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

		if !foundDomainMatch {
			logger.Log(4, fmt.Sprintf("resolving %s locally", domain))
			resp, err := GetDNSResolverInstance().Lookup(r)
			if err != nil {
				if errors.Is(err, ErrNXDomain) {
					reply.Rcode = dns.RcodeNameError
				} else {
					reply.Rcode = dns.RcodeServerFailure
				}
			} else {
				reply.Authoritative = true
				reply.Answer = append(reply.Answer, resp)
			}
		}
	}

	_ = w.WriteMsg(reply)
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

	conn, err := dnsUDPConnPool.get(serverAddr)
	if err != nil {
		return nil, err
	}
	defer dnsUDPConnPool.put(serverAddr, conn)

	dnsConn := &dns.Conn{
		Conn:    conn,
		UDPSize: dns.DefaultMsgSize,
	}

	client := &dns.Client{Net: "udp", Timeout: time.Second * 3}
	resp, _, err := client.ExchangeWithConn(r, dnsConn)
	return resp, err
}
