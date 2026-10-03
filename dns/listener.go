package dns

import (
	"context"
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

// darwinDNSLoopbackAddr is the lo0 alias the DNS listener binds on macOS. It is
// the only address published as an OS nameserver there, because it keeps
// answering regardless of tunnel state.
const darwinDNSLoopbackAddr = "127.51.8.21"

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

// ListenerAddr returns the primary bound listener address, or "" when none is
// bound. Use this rather than reading AddrStr: listeners are started and stopped
// from the DNS apply worker, peer updates and connect/disconnect concurrently.
func (dnsServer *DNSServer) ListenerAddr() string {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	return dnsServer.AddrStr
}

// ListenerAddrs returns a snapshot of the bound listener addresses.
func (dnsServer *DNSServer) ListenerAddrs() []string {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	return append([]string(nil), dnsServer.AddrList...)
}

// Start binds the DNS listeners if they are not up, then applies OS DNS.
//
// The two halves are separable (see StartListeners) because applying OS DNS is
// the slow part: on macOS it shells out to networksetup per network service and
// blocks for seconds while the network stack is reconfiguring.
func (dnsServer *DNSServer) Start() {
	alreadyUp := dnsServer.StartListeners()

	dnsMutex.Lock()
	listeners := strings.Join(dnsServer.AddrList, ", ")
	bound := dnsServer.AddrStr != ""
	dnsMutex.Unlock()
	if !bound {
		return
	}

	if err := Configure(); err != nil {
		logger.Log(0, "error configuring dns settings:", err.Error())
		return
	}
	if alreadyUp {
		// Session restore / exit apply flips SplitDNS↔full based on CurrGwNmIP
		// without restarting listeners.
		logger.Log(0, "dns reconfigured (listener already up), listeners:", listeners)
		return
	}
	logger.Log(0, "dns configured, listeners:", listeners)
	slog.Info("DNS server listens on: ", "Info", listeners)
}

// StartListeners binds the DNS listeners without touching OS DNS, reporting
// whether they were already up. Callers that also need OS DNS installed either
// use Start or schedule the apply themselves, keeping the slow networksetup pass
// off interactive paths like connect, disconnect and logout.
func (dnsServer *DNSServer) StartListeners() (alreadyUp bool) {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	if dnsServer.AddrStr != "" {
		return true
	}

	if len(config.GetNodes()) == 0 {
		logger.Log(0, "dns start skipped: no nodes")
		return false
	}

	// macOS listens on the loopback alias only. Overlay WG addresses are never
	// published as OS nameservers there (see nameserversForOS), and they cannot
	// bind until the tunnel is up, so attempting them only logs bind failures.
	// Exit-node mode publishes this address system-wide (SplitDNS=false).
	if runtime.GOOS == "darwin" {
		ensureDarwinDNSLoopbackAlias()
		if !dnsServer.startListenerLocked(darwinDNSLoopbackAddr + ":53") {
			logger.Log(0, "dns: failed to bind macOS loopback listener", darwinDNSLoopbackAddr+":53")
		}
	} else {
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
	}

	if len(dnsServer.AddrList) == 0 || len(dnsServer.DnsServer) == 0 {
		logger.Log(0, "dns start aborted: no listeners bound")
	}
	return false
}

// ensureDarwinDNSLoopbackAlias adds the loopback alias on lo0 so the DNS listener
// can bind before WireGuard Create has run (or after the alias was dropped).
func ensureDarwinDNSLoopbackAlias() {
	cmd := exec.Command("ifconfig", "lo0", "alias", darwinDNSLoopbackAddr)
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
		// Keep watching: an overlay listener dies when its address goes away
		// with the tunnel, and a dead address must not stay published.
		go func() {
			if err := <-errCh; err != nil {
				logger.Log(0, "dns listener exited on", lIp+":", err.Error())
			}
			dnsServer.dropListener(srv)
		}()
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

// dropListener forgets a listener whose serve loop has exited, so its address
// is no longer published to the resolver. It matches on the server pointer
// rather than the address: a Stop/Start cycle can rebind the same address, and
// a late watcher from the previous generation must not remove the new listener.
func (dnsServer *DNSServer) dropListener(srv *dns.Server) {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	idx := slices.Index(dnsServer.DnsServer, srv)
	if idx < 0 {
		return
	}
	addr := srv.Addr
	dnsServer.DnsServer = slices.Delete(dnsServer.DnsServer, idx, idx+1)
	dnsServer.AddrList = slices.DeleteFunc(dnsServer.AddrList, func(a string) bool { return a == addr })

	dnsServer.AddrStr = ""
	if len(dnsServer.AddrList) > 0 {
		dnsServer.AddrStr = dnsServer.AddrList[0]
	}
}

// SyncForNodeChange brings the DNS listeners in line with the current node set
// after a connect or disconnect, doing the least work that can still be correct.
//
// This only touches listeners. OS DNS must be applied separately afterwards, and
// on interactive paths that should be scheduled rather than awaited: a single
// networksetup pass costs seconds while the network stack is reconfiguring, which
// is exactly when connect and disconnect run.
//
// With no nodes left the listeners have to go. Otherwise they only need
// rebuilding when the bind set depends on node addresses — on macOS it does not,
// since the bind is a fixed loopback alias, so a running listener already serves
// the new node set.
func SyncForNodeChange() {
	server := config.GetServer(config.CurrServer)
	if server == nil || !server.ManageDNS {
		return
	}
	instance := GetDNSServerInstance()
	if len(config.GetNodes()) == 0 {
		instance.StopListeners()
		return
	}
	running := len(instance.ListenerAddrs()) > 0
	if running && !bindsFollowNodeAddrs() {
		return
	}
	if running {
		instance.StopListeners()
	}
	instance.StartListeners()
}

// bindsFollowNodeAddrs reports whether the listener binds overlay node
// addresses, and therefore has to be rebound when the node set changes.
func bindsFollowNodeAddrs() bool {
	return runtime.GOOS != "darwin"
}

// Stop removes OS DNS and shuts the listeners down.
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

	dnsServer.stopListenersLocked()
}

// StopListeners shuts the listeners down and forgets their addresses without
// touching OS DNS, so a caller on an interactive path does not wait on the slow
// networksetup pass. Whoever calls this owns removing the OS entries afterwards;
// leaving them behind points the resolver at a listener that is gone.
func (dnsServer *DNSServer) StopListeners() {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()
	dnsServer.stopListenersLocked()
}

func (dnsServer *DNSServer) stopListenersLocked() {
	if len(dnsServer.DnsServer) == 0 {
		return
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
