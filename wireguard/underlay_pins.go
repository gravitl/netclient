package wireguard

import (
	"net"
	"sort"
	"sync"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
)

// underlayPinOps installs and removes a single LAN host route.
type underlayPinOps struct {
	// install routes ip via `via`, replacing any route already present for ip.
	install func(ip net.IP, via string) error
	remove  func(ip net.IP, via string)
}

var (
	underlayPinsMu sync.Mutex
	// underlayPinsArmed gates installs so a refresh racing teardown (the IGW
	// monitor is stopped only after routes are reset) cannot re-add pins.
	// Unknown until first use, then seeded from the persisted exit state.
	underlayPinsArmed, underlayPinsArmKnown bool
)

// armUnderlayPins allows pin installs; called when exit routing is being set.
func armUnderlayPins() {
	underlayPinsMu.Lock()
	defer underlayPinsMu.Unlock()
	underlayPinsArmed, underlayPinsArmKnown = true, true
}

func underlayPinsArmedLocked(nc *config.Config) bool {
	if !underlayPinsArmKnown {
		underlayPinsArmKnown = true
		underlayPinsArmed = len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0
	}
	return underlayPinsArmed
}

// persistUnderlayPins is swapped out in tests so they do not write netclient.json.
var persistUnderlayPins = func() {
	if err := config.WriteNetclientConfig(); err != nil {
		slog.Warn("failed to persist underlay pins", "error", err)
	}
}

func isV6Pin(ip net.IP) bool { return ip.To4() == nil }

// viaGateway pins every IP via gw, or nothing when gw is unknown.
func viaGateway(gw net.IP) func(net.IP) string {
	return func(net.IP) string {
		if len(gw) == 0 || gw.IsUnspecified() {
			return ""
		}
		return gw.String()
	}
}

// canPruneUnderlayPins reports whether the peer view is complete enough to
// treat "not desired" as "stale". While HostPeers is being reloaded the exit's
// own endpoint is missing, and pruning then would drop the pin carrying the
// WireGuard handshake.
func canPruneUnderlayPins(exitPublicKey string) bool {
	return len(InternetGwHostIPs(exitPublicKey)) > 0
}

// reconcileUnderlayPins makes the recorded pins of one address family equal
// desired: pins no longer wanted are removed (only when prune is set), pins
// whose next hop changed (e.g. after a Wi-Fi switch) are reinstalled, missing
// ones are added. viaFor returns "" for an IP that cannot be pinned right now.
func reconcileUnderlayPins(v6 bool, desired []net.IP, viaFor func(net.IP) string, prune bool, ops underlayPinOps) {
	underlayPinsMu.Lock()
	defer underlayPinsMu.Unlock()
	nc := config.Netclient()
	if nc == nil || !underlayPinsArmedLocked(nc) {
		return
	}

	if !prune {
		desired = append([]net.IP(nil), desired...)
		for _, p := range nc.UnderlayPins {
			if ip := net.ParseIP(p.IP); ip != nil {
				desired = append(desired, ip)
			}
		}
	}
	want := make(map[string]string)
	wantIP := make(map[string]net.IP)
	for _, ip := range desired {
		if len(ip) == 0 || ip.IsUnspecified() || isV6Pin(ip) != v6 {
			continue
		}
		if via := viaFor(ip); via != "" {
			want[ip.String()] = via
			wantIP[ip.String()] = ip
		}
	}

	changed := false
	kept := make([]config.UnderlayPin, 0, len(nc.UnderlayPins)+len(want))
	prevVia := make(map[string]string)
	for _, p := range nc.UnderlayPins {
		ip := net.ParseIP(p.IP)
		if ip == nil {
			changed = true
			continue
		}
		if isV6Pin(ip) != v6 {
			kept = append(kept, p)
			continue
		}
		via, ok := want[p.IP]
		switch {
		case ok && via == p.Via:
			kept = append(kept, p)
			delete(want, p.IP)
		case ok:
			prevVia[p.IP] = p.Via
		default:
			ops.remove(ip, p.Via)
			slog.Info("removed stale underlay pin", "ip", p.IP, "via", p.Via)
			changed = true
		}
	}

	ips := make([]string, 0, len(want))
	for s := range want {
		ips = append(ips, s)
	}
	sort.Strings(ips)
	for _, s := range ips {
		via := want[s]
		if err := ops.install(wantIP[s], via); err != nil {
			slog.Error("failed to pin peer underlay via LAN", "ip", s, "via", via, "error", err)
			// The old route (if any) is still installed; keep it recorded so
			// teardown removes it.
			if old, ok := prevVia[s]; ok {
				kept = append(kept, config.UnderlayPin{IP: s, Via: old})
			}
			continue
		}
		if old, ok := prevVia[s]; ok {
			slog.Info("moved underlay pin to new LAN next hop", "ip", s, "old", old, "new", via)
		} else {
			slog.Info("pinning peer underlay via LAN", "ip", s, "via", via)
		}
		kept = append(kept, config.UnderlayPin{IP: s, Via: via})
		changed = true
	}

	nc.UnderlayPins = kept
	if changed {
		persistUnderlayPins()
	}
}

// removeUnderlayPins removes every recorded pin of one address family. With
// no record (config written by an older netclient) it falls back to the pins
// the current peer set implies, which is the best guess available.
func removeUnderlayPins(v6 bool, ops underlayPinOps) {
	underlayPinsMu.Lock()
	defer underlayPinsMu.Unlock()
	underlayPinsArmed, underlayPinsArmKnown = false, true
	nc := config.Netclient()
	if nc == nil {
		return
	}

	kept := make([]config.UnderlayPin, 0, len(nc.UnderlayPins))
	removed := 0
	for _, p := range nc.UnderlayPins {
		ip := net.ParseIP(p.IP)
		if ip == nil {
			continue
		}
		if isV6Pin(ip) != v6 {
			kept = append(kept, p)
			continue
		}
		ops.remove(ip, p.Via)
		removed++
	}
	if removed == 0 {
		for _, ip := range CollectUnderlayPinIPs() {
			if isV6Pin(ip) == v6 {
				ops.remove(ip, "")
			}
		}
	}
	nc.UnderlayPins = kept
	if removed > 0 {
		persistUnderlayPins()
	}
}
