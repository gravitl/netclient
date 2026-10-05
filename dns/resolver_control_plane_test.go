package dns

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInternetGwDNSServer(t *testing.T) {
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	nc := config.Config{}
	config.UpdateNetclient(nc)
	assert.Empty(t, internetGwDNSServer())

	nc.CurrGwNmIP = net.ParseIP("100.64.0.1")
	config.UpdateNetclient(nc)
	assert.Equal(t, "100.64.0.1", internetGwDNSServer())
}

func TestIpv4OnlyInternetExitStripsAAAA(t *testing.T) {
	prev := config.Netclient()
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
	})

	nc := config.Config{}
	nc.CurrGwNmIP = net.ParseIP("100.64.0.1")
	nc.CurrGwNmIP6 = nil
	config.UpdateNetclient(nc)
	assert.True(t, ipv4OnlyInternetExit())

	rrs := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ex.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.1").To4()},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ex.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")},
	}
	got := stripAAAARecords(rrs)
	require.Len(t, got, 1)
	_, ok := got[0].(*dns.A)
	assert.True(t, ok)

	nc.CurrGwNmIP6 = net.ParseIP("fd00::1")
	config.UpdateNetclient(nc)
	assert.False(t, ipv4OnlyInternetExit())
}

func TestControlPlaneAnswersFromCache(t *testing.T) {
	prevServer := config.CurrServer
	t.Cleanup(func() {
		config.SetLookupControlPlaneIPsForTest(nil)
		config.CurrServer = prevServer
		config.DeleteServer("dns-cp-test")
	})

	config.SetLookupControlPlaneIPsForTest(func(host string) ([]net.IP, error) {
		if host == "api.dns.test" {
			return []net.IP{net.ParseIP("203.0.113.40")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	})
	config.CurrServer = "dns-cp-test"
	config.UpdateServerConfig(&models.ServerConfig{
		Server: "dns-cp-test",
		API:    "api.dns.test:443",
		Broker: "broker.dns.test:8883",
	})
	require.True(t, config.RefreshControlPlaneEndpoints(config.GetServer("dns-cp-test")))

	msg := new(dns.Msg)
	msg.SetQuestion("api.dns.test.", dns.TypeA)
	got := controlPlaneAnswers(msg)
	require.Len(t, got, 1)
	a, ok := got[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "203.0.113.40", a.A.String())
}

// After an exit is torn down OS DNS can still send every name to the listener;
// the API hostname must keep resolving or the client cannot recover.
func TestResolveControlPlaneFallbackFillsEmptyReply(t *testing.T) {
	prevServer := config.CurrServer
	t.Cleanup(func() {
		config.SetLookupControlPlaneIPsForTest(nil)
		config.CurrServer = prevServer
		config.DeleteServer("dns-cp-fallback-test")
	})

	config.SetLookupControlPlaneIPsForTest(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.41")}, nil
	})
	config.CurrServer = "dns-cp-fallback-test"
	config.UpdateServerConfig(&models.ServerConfig{
		Server: "dns-cp-fallback-test",
		API:    "api.fallback.test:443",
		Broker: "broker.fallback.test:8883",
	})
	require.True(t, config.RefreshControlPlaneEndpoints(config.GetServer("dns-cp-fallback-test")))

	q := new(dns.Msg)
	q.SetQuestion("api.fallback.test.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Rcode = dns.RcodeNameError
	resolveControlPlaneFallback(q, reply)
	require.Len(t, reply.Answer, 1)
	assert.Equal(t, dns.RcodeSuccess, reply.Rcode)
	assert.Equal(t, "203.0.113.41", reply.Answer[0].(*dns.A).A.String())

	existing := &dns.A{Hdr: dns.RR_Header{Name: "api.fallback.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.1").To4()}
	reply = new(dns.Msg)
	reply.SetReply(q)
	reply.Answer = []dns.RR{existing}
	resolveControlPlaneFallback(q, reply)
	require.Len(t, reply.Answer, 1, "an existing answer must not be overridden")
}
