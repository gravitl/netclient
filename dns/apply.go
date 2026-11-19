package dns

import (
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Change is how the server's DNS config differs from what we have stored.
type Change int

const (
	changeUnchanged Change = iota
	changeStart
	changeStop
	changeUpdate
)

var (
	applyMu      sync.Mutex
	applyPending bool
	applyRunning bool
)

func logElapsed(label string) func() {
	start := time.Now()
	return func() {
		logger.Log(0, fmt.Sprintf("%s took %s", label, time.Since(start).Round(time.Millisecond)))
	}
}

// ReconfigureNow rebinds listeners to the current node set and reapplies OS DNS.
// Call it after join, disconnect, or a netmaker interface reset — once peers and
// exit routes are back, because full vs split DNS follows CurrGw.
//
// server is the network's server (config.GetServer(node.Server)). Callers with
// no network context may pass nil; CurrServer is used only then. OS DNS is
// removed only when no connected network still manages it, so a nil or
// unmanaged CurrServer cannot wipe resolver state another network needs.
func ReconfigureNow(server *config.Server) {
	if server == nil {
		server = config.GetServer(config.CurrServer)
	}
	if !anyConnectedNetworkManagesDNS() {
		GetDNSServerInstance().Stop()
		return
	}
	// This server is nil or does not manage DNS, but another connected network
	// does. Leave that resolver state in place.
	if server == nil || !server.ManageDNS {
		return
	}
	SyncForNodeChange()
	ScheduleReconfigure()
}

// anyConnectedNetworkManagesDNS reports whether a locally connected node
// belongs to a server that has ManageDNS set.
func anyConnectedNetworkManagesDNS() bool {
	for _, node := range config.GetNodes() {
		if !node.Connected {
			continue
		}
		srv := config.GetServer(node.Server)
		if srv != nil && srv.ManageDNS {
			return true
		}
	}
	return false
}

// ScheduleReconfigure applies OS DNS off the caller's goroutine, coalescing
// bursts into a single pass over the latest state.
//
// Installing OS DNS on macOS shells out to networksetup for every network
// service, and we necessarily do it while the network stack is mid-reconfigure —
// right after exit routes move. Measured there a single pass costs 7-15s, against
// 0.12s on an idle system, and connect/disconnect/logout blocked on it for their
// whole duration. Desired state is recomputed inside the apply, so coalescing
// converges on the final state instead of replaying intermediate ones.
//
// Callers that must observe DNS installed before returning should still call
// ReconfigureAfterRouting directly.
func ScheduleReconfigure() {
	applyMu.Lock()
	defer applyMu.Unlock()
	applyPending = true
	if applyRunning {
		return
	}
	applyRunning = true
	go func() {
		for {
			applyMu.Lock()
			if !applyPending {
				applyRunning = false
				applyMu.Unlock()
				return
			}
			applyPending = false
			applyMu.Unlock()
			ReconfigureAfterRouting()
		}
	}()
}

// ReconfigureAfterRouting re-runs OS DNS setup after exit-node routing changes.
// SplitDNS flips with CurrGwNmIP even when nameserver lists are unchanged.
// Always call this after clearing an exit — even if CurrGwNmIP was already nil —
// so system DNS is not left pointing at the Netmaker listener.
func ReconfigureAfterRouting() {
	defer logElapsed("dns reconfigure")()
	server := config.GetServer(config.CurrServer)
	manageDNS := server != nil && server.ManageDNS
	anyConnected := config.AnyNodeConnected()
	// Exit apply often runs before DNS Start during daemon bring-up. When
	// listeners are already up, still add any missing overlay binds for newly
	// connected networks (StartListeners is additive on Linux/Windows).
	// With nothing connected (logout, last disconnect) never start: macOS binds
	// its loopback listener regardless of Connected and would reinstall OS DNS.
	if manageDNS && anyConnected {
		if GetDNSServerInstance().ListenerAddr() == "" {
			GetDNSServerInstance().Start()
		} else {
			GetDNSServerInstance().StartListeners()
		}
	}
	if !anyConnected || GetDNSServerInstance().ListenerAddr() == "" {
		// No connected network, or listener still down: strip any leftover
		// Netmaker OS DNS (NRPT on Windows).
		GetDNSServerInstance().StopListeners()
		done := logElapsed("os dns reset")
		err := ResetOSConfig()
		done()
		if err != nil {
			slog.Warn("failed to reset os dns after routing change", "error", err)
		}
		flushCacheTimed()
		return
	}
	// Configure refreshes SplitDNS↔full from CurrGwNmIP and publishes all
	// current listener addresses as nameservers.
	done := logElapsed("os dns configure")
	err := Configure()
	done()
	if err != nil {
		// Do not ResetOSConfig here — a transient Configure failure would wipe
		// working DNS, especially on macOS where only loopback is published.
		slog.Warn("failed to reconfigure dns after routing change", "error", err)
		return
	}
	flushCacheTimed()
}

func flushCacheTimed() {
	defer logElapsed("dns cache flush")()
	FlushCache()
}

// DiffServer copies incoming DNS fields onto server when they differ from
// what is stored. changed is true when the caller must write the server config.
func DiffServer(server *config.Server, manageDNS bool, defaultDomain string, nameServers []string, dnsNameservers []models.Nameserver) (Change, bool) {
	if server.ManageDNS {
		if !manageDNS {
			server.ManageDNS = false
			server.DefaultDomain = ""
			server.NameServers = nil
			server.DnsNameservers = nil
			return changeStop, true
		}
		if server.DefaultDomain != defaultDomain ||
			len(server.DnsNameservers) != len(dnsNameservers) ||
			!reflect.DeepEqual(server.DnsNameservers, dnsNameservers) {
			server.DefaultDomain = defaultDomain
			server.NameServers = nameServers
			server.DnsNameservers = dnsNameservers
			return changeUpdate, true
		}
		return changeUnchanged, false
	}
	if manageDNS {
		server.ManageDNS = true
		server.DefaultDomain = defaultDomain
		server.NameServers = nameServers
		server.DnsNameservers = dnsNameservers
		return changeStart, true
	}
	return changeUnchanged, false
}

// ApplyForUpdate installs or clears OS DNS after a peer update or fallback
// pull. Start and Stop already apply or clear it. Otherwise schedule a reapply
// only when nameservers changed, exit routes moved, or the listener should be
// up and is not. A pin-only update leaves exitRoutingChanged false and does
// not call networksetup.
//
// Call after the server config has been written, so Start reads the new nameservers.
func ApplyForUpdate(server *config.Server, change Change, exitRoutingChanged bool) {
	switch change {
	case changeStart:
		GetDNSServerInstance().Start()
	case changeStop:
		GetDNSServerInstance().Stop()
	}
	// OS DNS is system-wide while an exit is installed and split otherwise.
	// Reapply when nameservers changed or this update installed, reinstalled,
	// or removed exit routes. Start/Stop already apply or clear it.
	// Also reapply when we should be serving DNS but the listener is down —
	// connect's own apply can lose the race with this update's Restore.
	listenerDown := server.ManageDNS && config.AnyNodeConnected() && GetDNSServerInstance().ListenerAddr() == ""
	if change != changeStart && change != changeStop && (change == changeUpdate || exitRoutingChanged || listenerDown) {
		ScheduleReconfigure()
	}
}
