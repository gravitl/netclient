package dns

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"

	dnscache "github.com/gravitl/netclient/dns/cache"
	dnsconfig "github.com/gravitl/netclient/dns/config"
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
	cacheManager = dnscache.NewManager()
}

func Init() error {
	var err error
	configManager, err = dnsconfig.NewManager(dnsconfig.CleanupResidualInterfaceConfigs(ncutils.GetInterfaceName()))
	return err
}

// GetInstance
func GetDNSServerInstance() *DNSServer {
	return dnsServer
}

// Start the DNS listener
func (dnsServer *DNSServer) Start() {
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
			lAddr := []string{}
			if node.Address.IP != nil {
				lAddr = append(lAddr, node.Address.IP.String()+":53")
			}
			if node.Address6.IP != nil {
				lAddr = append(lAddr, "["+node.Address6.IP.String()+"]:53")
			}

			if len(lAddr) == 0 {
				continue
			}
			for _, lIp := range lAddr {
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
	}

	time.Sleep(time.Second * 1)
	//if listener failed to start, do not make DNS changes
	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		return
	}

	err := Configure()
	if err != nil {
		logger.Log(0, "error configuring dns settings:", err.Error())
	}

	slog.Info("DNS server listens on: ", "Info", dnsServer.AddrStr)
}

// Stop the DNS listener
func (dnsServer *DNSServer) Stop() {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		return
	}

	err := configManager.Configure(ncutils.GetInterfaceName(), dnsconfig.Config{
		Remove: true,
	})
	if err != nil {
		logger.Log(0, "error resetting dns config:", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for _, v := range dnsServer.DnsServer {
		err := v.ShutdownContext(ctx)
		if err != nil {
			logger.Log(0, "error shutting down dns server:", err.Error())
		}
	}

	dnsServer.AddrStr = ""
	dnsServer.AddrList = []string{}
	dnsServer.DnsServer = []*dns.Server{}
}
