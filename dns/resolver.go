package dns

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
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
	slog.Info("receiving DNS query request", "Info", r.Question[0])
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.RecursionDesired = true
	reply.Rcode = dns.RcodeSuccess
	reply.Authoritative = true

	resp, err := GetDNSResolverInstance().Lookup(r)
	if err != nil && errors.Is(err, ErrNXDomain) {
		nslist := config.Netclient().NameServers
		if config.Netclient().CurrGwNmIP != nil {
			nslist = []string{}
			nslist = append(nslist, config.Netclient().CurrGwNmIP.String())
		} else if isInternetGW() {
			nslist = []string{}
			nslist = append(nslist, "8.8.8.8")
			nslist = append(nslist, "8.8.4.4")
			nslist = append(nslist, "2001:4860:4860::8888")
			nslist = append(nslist, "2001:4860:4860::8844")
		}

		gotResult := false
		client := &dns.Client{}
		for _, v := range nslist {
			if strings.Contains(v, ":") {
				v = "[" + v + "]"
			}
			resp, _, err := client.Exchange(r, v+":53")
			if err != nil {
				continue
			}

			if resp.Rcode != dns.RcodeSuccess {
				continue
			}

			if len(resp.Answer) > 0 {
				reply.Answer = append(reply.Answer, resp.Answer...)
				gotResult = true
				break
			}
		}

		if !gotResult {
			reply.Rcode = dns.RcodeNameError
		}
	}

	if resp != nil {
		reply.Answer = append(reply.Answer, resp)
	}

	err = w.WriteMsg(reply)
	if err != nil {
		slog.Error("write DNS response message error: ", "error", err.Error())
	}
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
