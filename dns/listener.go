package dns

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"slices"
	"strings"
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
	if err != nil {
		logger.Log(0, "error initializing dns manager with residual cleanup:", err.Error())
		// Residual cleanup failure must not disable OS DNS entirely (NoopManager).
		configManager, err = dnsconfig.NewManager()
		if err != nil {
			logger.Log(0, "error initializing dns manager:", err.Error())
			configManager = &dnsconfig.NoopManager{}
			return err
		}
	}

	return nil
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
		// Already listening — still refresh OS DNS. Session restore / exit apply
		// flips SplitDNS↔full based on CurrGwNmIP without restarting listeners.
		if err := Configure(); err != nil {
			logger.Log(0, "error reconfiguring dns settings:", err.Error())
		} else {
			logger.Log(0, "dns reconfigured (listener already up), listeners:", strings.Join(dnsServer.AddrList, ", "))
		}
		return
	}

	if len(config.GetNodes()) == 0 {
		logger.Log(0, "dns start skipped: no nodes")
		return
	}

	// On macOS, ensure lo0 alias then bind loopback first. Exit-node mode
	// publishes this address system-wide (SplitDNS=false / networksetup).
	if runtime.GOOS == "darwin" {
		ensureDarwinDNSLoopbackAlias()
		if !dnsServer.startListenerLocked("127.51.8.21:53") {
			logger.Log(0, "dns: failed to bind macOS loopback listener 127.51.8.21:53")
		}
	}

	for _, v := range config.GetNodes() {
		node := v
		if !v.Connected {
			continue
		}
		if node.Address.IP != nil {
			dnsServer.startListenerLocked(node.Address.IP.String() + ":53")
		}
		if node.Address6.IP != nil {
			dnsServer.startListenerLocked("[" + node.Address6.IP.String() + "]:53")
		}
	}

	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		logger.Log(0, "dns start aborted: no listeners bound")
		return
	}
	if runtime.GOOS == "darwin" && !dnsServer.hasLoopbackListener() {
		logger.Log(0, "dns: macOS loopback listener not up; OS DNS may fall back to overlay addresses")
	}

	err := Configure()
	if err != nil {
		logger.Log(0, "error configuring dns settings:", err.Error())
	} else {
		logger.Log(0, "dns configured, listeners:", strings.Join(dnsServer.AddrList, ", "))
	}

	slog.Info("DNS server listens on: ", "Info", dnsServer.AddrList)
}

// ensureDarwinDNSLoopbackAlias adds 127.51.8.21 on lo0 so the DNS listener can bind
// before WireGuard Create has run (or after the alias was dropped).
func ensureDarwinDNSLoopbackAlias() {
	cmd := exec.Command("ifconfig", "lo0", "alias", "127.51.8.21")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Alias may already exist; only log unexpected failures.
		slog.Debug("lo0 dns alias", "error", err, "output", string(out))
	}
}

// startListenerLocked binds a UDP DNS listener and only records it after the
// socket is actually listening. Caller must hold dnsMutex.
func (dnsServer *DNSServer) startListenerLocked(lIp string) bool {
	dns.HandleFunc(".", handleDNSRequest)

	started := make(chan struct{})
	errCh := make(chan error, 1)
	srv := &dns.Server{
		Net:     "udp",
		Addr:    lIp,
		UDPSize: 65535,
		NotifyStartedFunc: func() {
			close(started)
		},
	}
	// ReusePort/ReuseAddr can fight mDNSResponder on darwin port 53.
	if runtime.GOOS != "darwin" {
		srv.ReusePort = true
		srv.ReuseAddr = true
	}

	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-started:
		dnsServer.AddrStr = lIp
		dnsServer.AddrList = append(dnsServer.AddrList, lIp)
		dnsServer.DnsServer = append(dnsServer.DnsServer, srv)
		return true
	case err := <-errCh:
		logger.Log(0, "error in starting dns server on", lIp+":", err.Error())
		return false
	case <-time.After(3 * time.Second):
		logger.Log(0, "timeout starting dns server on", lIp)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.ShutdownContext(ctx)
		cancel()
		return false
	}
}

func (dnsServer *DNSServer) hasLoopbackListener() bool {
	for _, addr := range dnsServer.AddrList {
		ip := getIpFromServerString(addr)
		if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
			return true
		}
	}
	return false
}

// dropListener forgets a listener that failed to bind. It removes by address
// rather than by position because the listener that failed is not necessarily
// the one appended last, and the surviving addresses are what get published to
// the resolver.
func (dnsServer *DNSServer) dropListener(addr string) {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	dnsServer.AddrList = slices.DeleteFunc(dnsServer.AddrList, func(a string) bool { return a == addr })
	dnsServer.DnsServer = slices.DeleteFunc(dnsServer.DnsServer, func(s *dns.Server) bool { return s.Addr == addr })

	dnsServer.AddrStr = ""
	if len(dnsServer.AddrList) > 0 {
		dnsServer.AddrStr = dnsServer.AddrList[0]
	}
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
