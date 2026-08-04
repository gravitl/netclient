// Package proxyegress wires github.com/gravitl/proxy/l7 into netclient for
// proxy-mode app egress (HTTP CONNECT via egress gateway, no domain IP routes).
package proxyegress

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/proxy/l7"
	"github.com/gravitl/proxy/sysproxy"
	"golang.org/x/exp/slog"
)

const localForwardPort = 17832

var (
	mu sync.RWMutex

	l7Srv     *l7.Server
	l7Cancel  context.CancelFunc
	fwdCancel context.CancelFunc
	fwdLn     net.Listener

	// domain -> GW proxy mesh addr (host:port)
	domainToProxy map[string]string
	// domains this host should allow on the GW l7.Server
	gwAllowlist []string
	listenAddr  string // mesh addr for local GW l7.Server
)

// ApplyProxyRoutes reconciles gateway L7 server and local CONNECT forwarder from peer update.
func ApplyProxyRoutes(routes []models.EgressProxyRoute) {
	mu.Lock()
	defer mu.Unlock()

	domainToProxy = make(map[string]string)
	gwAllow := make(map[string]struct{})
	listenAddr = ""
	localNodes := localNodeIDSet()

	for _, r := range routes {
		if r.ProxyAddr == "" || len(r.Domains) == 0 {
			continue
		}
		for _, d := range r.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			domainToProxy[d] = r.ProxyAddr
			if localNodes[r.NodeID] {
				gwAllow[d] = struct{}{}
				if listenAddr == "" {
					listenAddr = r.ProxyAddr
				}
			}
		}
	}
	gwAllowlist = make([]string, 0, len(gwAllow))
	for d := range gwAllow {
		gwAllowlist = append(gwAllowlist, d)
	}

	reconcileGatewayLocked()
	reconcileForwarderLocked()
	writePACLocked()
}

// Stop tears down L7 gateway/forwarder and clears the OS system PAC.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopGatewayLocked()
	stopForwarderLocked()
	domainToProxy = nil
	gwAllowlist = nil
	listenAddr = ""
	_ = os.Remove(PACPath())
	if err := sysproxy.Clear(sysProxyOpts()); err != nil {
		slog.Warn("egress proxy: clear system PAC", "error", err)
	}
}

func localNodeIDSet() map[string]bool {
	m := make(map[string]bool)
	for _, n := range config.GetNodes() {
		m[n.ID.String()] = true
	}
	return m
}

func reconcileGatewayLocked() {
	wantListen := listenAddr != "" && len(gwAllowlist) > 0
	if !wantListen {
		stopGatewayLocked()
		return
	}
	// Restart if listen addr or allowlist changed — simplest: always restart.
	stopGatewayLocked()
	matcher := l7.Allowlist{Domains: append([]string(nil), gwAllowlist...)}
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr: listenAddr,
		Matcher:    matcher,
		Logger:     slogAdapter{},
	})
	if err != nil {
		slog.Error("egress proxy: new l7 server", "error", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		cancel()
		slog.Error("egress proxy: start l7 server", "addr", listenAddr, "error", err)
		return
	}
	l7Srv = srv
	l7Cancel = cancel
	slog.Info("egress proxy: l7.Server listening", "addr", srv.Addr(), "domains", len(gwAllowlist))
}

func stopGatewayLocked() {
	if l7Cancel != nil {
		l7Cancel()
		l7Cancel = nil
	}
	if l7Srv != nil {
		_ = l7Srv.Stop(context.Background())
		l7Srv = nil
	}
}

type slogAdapter struct{}

func (slogAdapter) Debug(msg string, kv ...any) { slog.Debug(msg, kv...) }
func (slogAdapter) Info(msg string, kv ...any)  { slog.Info(msg, kv...) }
func (slogAdapter) Warn(msg string, kv ...any)  { slog.Warn(msg, kv...) }
func (slogAdapter) Error(msg string, kv ...any) { slog.Error(msg, kv...) }

// LocalProxyURL is the PAC / HTTPS_PROXY target for apps on this host.
func LocalProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", localForwardPort)
}

// PACPath returns the on-disk PAC file path.
func PACPath() string {
	return filepath.Join(config.GetNetclientPath(), "egress_proxy.pac")
}

func sysProxyOpts() sysproxy.Options {
	return sysproxy.Options{
		StateDir:          config.GetNetclientPath(),
		LocalProxyURL:     LocalProxyURL(),
		ProfileScriptName: "netclient-egress-proxy.sh",
	}
}

func writePACLocked() {
	path := PACPath()
	opts := sysProxyOpts()
	if len(domainToProxy) == 0 {
		_ = os.Remove(path)
		if err := sysproxy.Clear(opts); err != nil {
			slog.Warn("egress proxy: clear system PAC", "error", err)
		}
		return
	}
	domains := make([]string, 0, len(domainToProxy))
	for d := range domainToProxy {
		domains = append(domains, d)
	}
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", localForwardPort)
	if err := sysproxy.WritePAC(path, domains, proxyAddr); err != nil {
		slog.Warn("egress proxy: write PAC", "path", path, "error", err)
		return
	}
	slog.Info("egress proxy: PAC written", "path", path, "local_proxy", LocalProxyURL())
	if err := sysproxy.Apply(path, opts); err != nil {
		slog.Warn("egress proxy: apply system PAC", "error", err)
		return
	}
	slog.Info("egress proxy: system PAC applied", "pac", path)
}
