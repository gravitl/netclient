package dns

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

var dnsMutex = sync.Mutex{} // used to mutex functions of the DNS

type DNSServer struct {
	DnsServer []*dns.Server
	AddrList  []string
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

// Start the DNS listener
func (dnsServer *DNSServer) Start() {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if dnsServer.AddrStr != "" {
		return
	}

	if len(config.GetNodes()) == 0 {
		return
	}

	for _, v := range config.GetNodes() {
		node := v
		if v.Connected {

			lIp := ""
			if node.Address6.IP != nil {
				lIp = "[" + node.Address6.IP.String() + "]:53"
			}
			if node.Address.IP != nil {
				lIp = node.Address.IP.String() + ":53"
			}

			if lIp == "" {
				continue
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
			dnsServer.AddrList = append(dnsServer.AddrList, lIp)
			dnsServer.DnsServer = append(dnsServer.DnsServer, srv)

			go func(dnsServer *DNSServer) {
				err := srv.ListenAndServe()
				if err != nil {
					slog.Error("error in starting dns server", "error", lIp, err.Error())
					dnsServer.AddrStr = ""
					dnsServer.AddrList = slices.Delete(dnsServer.AddrList, len(dnsServer.AddrList)-1, len(dnsServer.AddrList))
					dnsServer.DnsServer = slices.Delete(dnsServer.DnsServer, len(dnsServer.DnsServer)-1, len(dnsServer.DnsServer))
				}
			}(dnsServer)
		}
	}

	time.Sleep(time.Second * 1)
	//if listener failed to start, do not make DNS changes
	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		return
	}

	//Setup DNS config for Linux
	if config.Netclient().Host.OS == "linux" || config.Netclient().Host.OS == "windows" {
		err := SetupDNSConfig()
		if err != nil {
			slog.Error("setup DNS config failed", "error", err.Error())
		}
	}

	slog.Info("DNS server listens on: ", "Info", dnsServer.AddrStr)
}

// Stop the DNS listener
func (dnsServer *DNSServer) Stop() {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		return
	}

	//restore DNS config for Linux
	if config.Netclient().Host.OS == "linux" || config.Netclient().Host.OS == "windows" {
		err := RestoreDNSConfig()
		if err != nil {
			slog.Warn("Restore DNS conig failed", "error", err.Error())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for _, v := range dnsServer.DnsServer {
		err := v.ShutdownContext(ctx)
		if err != nil {
			slog.Error("could not shutdown DNS server", "error", err.Error())
		}
	}

	dnsServer.AddrStr = ""
	dnsServer.AddrList = []string{}
	dnsServer.DnsServer = []*dns.Server{}
}
