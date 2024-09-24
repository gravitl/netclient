package dns

import (
	"context"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

var dnsMutex = sync.Mutex{} // used to mutex functions of the DNS

type DNSServer struct {
	DnsServer *dns.Server
	AddrStr   string
}

var dnsServer *DNSServer

func init() {
	dnsServer = &DNSServer{}
}

// GetInstance
func GetDNSServerInstance() *DNSServer {
	return dnsServer
}

func (dnsServer *DNSServer) Start() {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if dnsServer.AddrStr != "" {
		return
	}

	if len(config.GetNodes()) == 0 {
		return
	}

	var node config.Node
	for _, v := range config.GetNodes() {
		node = v
		break
	}

	lIp := ""
	if node.Address6.IP != nil {
		lIp = "[" + node.Address6.IP.String() + "]:53"
	}
	if node.Address.IP != nil {
		lIp = node.Address.IP.String() + ":53"
	}

	if lIp == "" {
		return
	}

	dns.HandleFunc(".", handleDNSRequest)

	srv := &dns.Server{
		Net:       "udp",
		Addr:      lIp,
		UDPSize:   65535,
		ReusePort: true,
		ReuseAddr: true,
	}

	dnsServer.AddrStr = lIp
	dnsServer.DnsServer = srv

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			slog.Error("error in starting dns server", "error", lIp, err.Error())
			dnsServer.AddrStr = ""
			dnsServer.DnsServer = nil
		}
	}()

	//Setup resolveconf for Linux
	if config.Netclient().Host.OS == "linux" {
		SetupResolvconf()
	}

	slog.Info("DNS server listens on: ", "Info", lIp)
}

func (dnsServer *DNSServer) Stop() {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if dnsServer.AddrStr == "" || dnsServer.DnsServer == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := dnsServer.DnsServer.ShutdownContext(ctx)
	if err != nil {
		slog.Error("could not shutdown DNS server", "error", err.Error())
	}

	dnsServer.AddrStr = ""
	dnsServer.DnsServer = nil
}
