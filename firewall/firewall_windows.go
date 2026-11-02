//go:build windows
// +build windows

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"golang.org/x/exp/slog"
)

const (
	testIPv4    = "1.1.1.1"
	testIPv6    = "2606:4700:4700::1111"
	ipv4Network = "0.0.0.0/0"
	ipv6Network = "::/0"

	// Legacy Defender Firewall group/names — removed on upgrade; kept for cleanup only.
	winFwACLGroup       = "Netmaker-ACL"
	winFwDNSUDPRuleName = "Netmaker-DNS-UDP"
)

// windowsManager implements egress via Hyper-V NetNat + IP forwarding, and
// peer/host + egress ACLs via the Windows Filtering Platform (WFP).
type windowsManager struct {
	mux          sync.Mutex
	engressRules serverrulestable
	ingRules     serverrulestable
	aclRules     serverrulestable
}

func newFirewall() (firewallController, error) {
	logger.Log(0, "using Windows NetNat + WFP ACLs...")
	if cfg := config.Netclient(); cfg != nil {
		cfg.FirewallInUse = schema.FIREWALL_NETNAT
	}
	return &windowsManager{
		engressRules: make(serverrulestable),
		ingRules:     make(serverrulestable),
		aclRules:     make(serverrulestable),
	}, nil
}

func (w *windowsManager) CreateChains() error {
	ensureWindowsACLBootstrap()
	return nil
}

func (w *windowsManager) ForwardRule() error {
	ensureWindowsACLBootstrap()
	return nil
}

func (w *windowsManager) AddDropRules([]ruleInfo) {}

func (w *windowsManager) InsertIngressRoutingRules(server string, ingressInfo models.IngressInfo) error {
	return nil
}
func (w *windowsManager) FetchRuleTable(server, ruleTableName string) ruletable {
	w.mux.Lock()
	defer w.mux.Unlock()
	var table serverrulestable
	switch ruleTableName {
	case egressTable:
		table = w.engressRules
	case ingressTable:
		table = w.ingRules
	case aclTable:
		table = w.aclRules
	default:
		return make(ruletable)
	}
	if table == nil {
		return make(ruletable)
	}
	if rt, ok := table[server]; ok {
		return rt
	}
	return make(ruletable)
}

func (w *windowsManager) SaveRules(server, ruleTableName string, ruleTable ruletable) {
	w.mux.Lock()
	defer w.mux.Unlock()
	var table serverrulestable
	switch ruleTableName {
	case egressTable:
		if w.engressRules == nil {
			w.engressRules = make(serverrulestable)
		}
		table = w.engressRules
	case ingressTable:
		if w.ingRules == nil {
			w.ingRules = make(serverrulestable)
		}
		table = w.ingRules
	case aclTable:
		if w.aclRules == nil {
			w.aclRules = make(serverrulestable)
		}
		table = w.aclRules
	default:
		return
	}
	table[server] = ruleTable
}

func (w *windowsManager) DeleteRuleTable(server, ruleTableName string) {
	w.mux.Lock()
	defer w.mux.Unlock()
	var table serverrulestable
	switch ruleTableName {
	case egressTable:
		table = w.engressRules
	case ingressTable:
		table = w.ingRules
	case aclTable:
		table = w.aclRules
	default:
		return
	}
	if table != nil {
		delete(table, server)
	}
}

func (w *windowsManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	ruleTable := w.FetchRuleTable(server, egressTable)
	defer w.SaveRules(server, egressTable, ruleTable)

	w.mux.Lock()
	defer w.mux.Unlock()

	ruleTable[egressInfo.EgressID] = rulesCfg{
		rulesMap:  make(map[string][]ruleInfo),
		extraInfo: egressInfo.EgressGWCfg,
	}

	wgIface := ncutils.GetInterfaceName()
	_ = local.EnableForwardingOnInterfaces(wgIface)

	egressGwRoutes := []ruleInfo{}
	natApplied := false

	for _, egressGwRange := range egressInfo.EgressGWCfg.RangesWithMetric {
		if _, shouldApply := shouldApplyVirtualNat(egressGwRange); shouldApply {
			slog.Warn("windows: virtual NAT is not supported; falling back to direct NAT where Nat=true",
				"egress", egressInfo.EgressID, "range", egressGwRange.Network)
		}

		lanIface, err := getWindowsInterfaceName(egressGwRange.Network)
		if err != nil {
			slog.Warn("windows: failed to resolve LAN interface for egress range",
				"range", egressGwRange.Network, "error", err)
		} else {
			_ = local.EnableForwardingOnInterfaces(lanIface)
			egressGwRoutes = append(egressGwRoutes, ruleInfo{
				rule:  []string{"forwarding", lanIface},
				table: "windows",
				chain: "forwarding",
			})
		}

		if !egressGwRange.Nat {
			continue
		}

		// One NetNat per egress ID using the mesh (internal) prefix — Hyper-V NetNat
		// SNATs traffic sourced from InternalIPInterfaceAddressPrefix when leaving the host.
		if natApplied {
			continue
		}
		meshPrefix := normalizeNetNatPrefix(egressInfo.Network.String())
		if !isIPv4CIDR(egressGwRange.Network) && egressInfo.Network6.IP != nil {
			meshPrefix = normalizeNetNatPrefix(egressInfo.Network6.String())
		}
		if meshPrefix == "" {
			slog.Warn("windows: missing mesh network prefix for NetNat", "egress", egressInfo.EgressID)
			continue
		}
		// Hyper-V NetNat only accepts an IPv4 InternalIPInterfaceAddressPrefix.
		// Skip rather than hand New-NetNat a v6 prefix it cannot use; a v4 range
		// on the same egress still gets its NetNat since natApplied stays false.
		if !isIPv4CIDR(meshPrefix) {
			slog.Warn("windows: IPv6 egress NAT is unsupported (NetNat is IPv4-only); skipping NAT for this range",
				"egress", egressInfo.EgressID, "range", egressGwRange.Network, "meshPrefix", meshPrefix)
			continue
		}
		name := netNatName(egressInfo.EgressID)
		if err := ensureNetNat(name, meshPrefix); err != nil {
			slog.Error("windows: failed to create NetNat for egress",
				"egress", egressInfo.EgressID, "name", name, "prefix", meshPrefix, "error", err)
			return fmt.Errorf("NetNat create failed: %w", err)
		}
		// Exit-node clients forward DNS here; keep WFP bootstrap allows present.
		ensureWindowsACLBootstrap()
		egressGwRoutes = append(egressGwRoutes, ruleInfo{
			rule:  []string{"netnat", name, meshPrefix},
			table: "windows",
			chain: "netnat",
		})
		natApplied = true
		slog.Info("windows: applied NetNat for egress", "egress", egressInfo.EgressID, "name", name, "prefix", meshPrefix)
	}

	ruleTable[egressInfo.EgressID].rulesMap[egressInfo.EgressID] = egressGwRoutes
	return nil
}

func (w *windowsManager) RemoveRoutingRules(server, ruletableName, peerKey string) error {
	rulesTable := w.FetchRuleTable(server, ruletableName)
	defer w.SaveRules(server, ruletableName, rulesTable)

	w.mux.Lock()
	defer w.mux.Unlock()

	cfg, ok := rulesTable[peerKey]
	if !ok {
		// Still try to remove NetNat by deterministic name for egress entries.
		if ruletableName == egressTable && !strings.Contains(peerKey, "acl#") {
			_ = removeNetNat(netNatName(peerKey))
		}
		return nil
	}
	lanIfaces := make([]string, 0)
	for _, rules := range cfg.rulesMap {
		for _, rule := range rules {
			if len(rule.rule) < 2 {
				continue
			}
			switch rule.rule[0] {
			case "forwarding":
				lanIfaces = append(lanIfaces, rule.rule[1])
			case "netnat":
				_ = removeNetNat(rule.rule[1])
			case "wfp":
				if id, err := strconv.ParseUint(rule.rule[1], 10, 64); err == nil {
					deleteWFPFiltersIfOpen([]uint64{id})
				}
			case "winfw":
				_ = removeWindowsFirewallRule(rule.rule[1])
			}
		}
	}
	delete(rulesTable, peerKey)
	// Drop LAN forwarding only when no remaining egress still needs that iface.
	// Never disable the netmaker adapter here — relay/hairpin still needs it.
	if ruletableName == egressTable {
		w.disableUnusedEgressForwardingLocked(lanIfaces)
	}
	return nil
}

// disableUnusedEgressForwardingLocked turns off Forwarding on LAN ifaces that
// are no longer referenced by any egress rule. Caller must hold w.mux.
func (w *windowsManager) disableUnusedEgressForwardingLocked(lanIfaces []string) {
	nm := ncutils.GetInterfaceName()
	seen := make(map[string]struct{})
	for _, iface := range lanIfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" || strings.EqualFold(iface, nm) {
			continue
		}
		key := strings.ToLower(iface)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if w.egressForwardingStillNeededLocked(iface) {
			continue
		}
		if err := local.DisableForwardingOnInterfaces(iface); err != nil {
			slog.Warn("windows: failed to disable forwarding on egress LAN iface",
				"iface", iface, "error", err)
		}
	}
}

// egressForwardingStillNeededLocked reports whether any egress entry still has
// a forwarding rule for iface. Caller must hold w.mux.
func (w *windowsManager) egressForwardingStillNeededLocked(iface string) bool {
	for _, serverTable := range w.engressRules {
		for _, cfg := range serverTable {
			for _, rules := range cfg.rulesMap {
				for _, rule := range rules {
					if len(rule.rule) >= 2 && rule.rule[0] == "forwarding" &&
						strings.EqualFold(rule.rule[1], iface) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (w *windowsManager) DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error {
	return nil
}

func (w *windowsManager) CleanRoutingRules(server, tableName string) {
	ruleTable := w.FetchRuleTable(server, tableName)
	for peerKey := range ruleTable {
		_ = w.RemoveRoutingRules(server, tableName, peerKey)
	}
	w.DeleteRuleTable(server, tableName)
}

func (w *windowsManager) FlushAll() {
	w.mux.Lock()
	defer w.mux.Unlock()
	start := time.Now()
	slog.Info("windows: flushing netmaker NetNat, WFP ACL filters, and IP forwarding")
	// Collect egress LAN ifaces before clearing rule tables so we can disable
	// Forwarding we previously enabled for NAT/egress.
	lanIfaces := collectEgressForwardingIfaces(w.engressRules)
	closeWFPEngine()
	// Same once-per-process migration cleanup as bootstrap (avoids a second
	// PowerShell sweep when Init does FlushAll then CreateChains/ForwardRule).
	cleanupLegacyDefenderACLRules()
	names, err := listNetmakerNetNats()
	if err != nil {
		slog.Warn("windows: failed listing NetNats during flush", "error", err)
	} else {
		for _, name := range names {
			if err := removeNetNat(name); err != nil {
				slog.Warn("windows: failed removing NetNat", "name", name, "error", err)
			}
		}
	}
	w.engressRules = make(serverrulestable)
	w.ingRules = make(serverrulestable)
	w.aclRules = make(serverrulestable)
	if len(lanIfaces) > 0 {
		if err := local.DisableForwardingOnInterfaces(lanIfaces...); err != nil {
			slog.Warn("windows: failed disabling egress LAN forwarding on flush", "error", err)
		}
	}
	// Daemon stop/reset: clear netmaker Forwarding + WeakHost (iface may already
	// be gone — DisableForwardingOnInterfaces treats that as benign).
	if err := local.DisableForwardingOnInterfaces(ncutils.GetInterfaceName()); err != nil {
		slog.Warn("windows: failed disabling netmaker forwarding on flush", "error", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		logger.Log(0, "windows firewall FlushAll took ", d.String())
	}
}

// collectEgressForwardingIfaces returns unique LAN iface aliases recorded under
// "forwarding" egress rules (excludes the netmaker adapter).
func collectEgressForwardingIfaces(tables serverrulestable) []string {
	nm := ncutils.GetInterfaceName()
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, serverTable := range tables {
		for _, cfg := range serverTable {
			for _, rules := range cfg.rulesMap {
				for _, rule := range rules {
					if len(rule.rule) < 2 || rule.rule[0] != "forwarding" {
						continue
					}
					iface := strings.TrimSpace(rule.rule[1])
					if iface == "" || strings.EqualFold(iface, nm) {
						continue
					}
					key := strings.ToLower(iface)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, iface)
				}
			}
		}
	}
	return out
}

func getWindowsInterfaceName(dstCIDR string) (string, error) {
	ip := dstCIDR
	// Default routes carry no address to probe, so substitute a well-known
	// off-link host of the matching family: a v4 probe would resolve ::/0 to the
	// v4 exit interface.
	if dstCIDR == ipv6Network {
		ip = testIPv6
	} else if dstCIDR == ipv4Network || dstCIDR == "*" {
		ip = testIPv4
	} else if host, _, err := net.ParseCIDR(dstCIDR); err == nil {
		ip = host.String()
	} else if parsed := net.ParseIP(dstCIDR); parsed != nil {
		ip = parsed.String()
	}
	escaped := strings.ReplaceAll(ip, "'", "''")
	ps := fmt.Sprintf(`$r = Find-NetRoute -RemoteIPAddress '%s' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $r) { throw 'route not found' }; $r.InterfaceAlias`, escaped)
	out, err := runPS(ps)
	if err != nil {
		return "", err
	}
	alias := strings.TrimSpace(out)
	if alias == "" {
		return "", fmt.Errorf("interface not found for %s", dstCIDR)
	}
	return alias, nil
}

// removeWindowsFirewallRule deletes a leftover Defender rule by name (migration cleanup).
func removeWindowsFirewallRule(name string) error {
	escaped := strings.ReplaceAll(name, "'", "''")
	ps := fmt.Sprintf(`Get-NetFirewallRule -Name '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`, escaped)
	_, err := runPS(ps)
	return err
}

// removeAllNetmakerACLFirewallRules clears Defender rules from the prior ACL implementation.
// Name/group filters only — never enumerate every firewall rule (that alone is often 5–15s).
func removeAllNetmakerACLFirewallRules() error {
	group := strings.ReplaceAll(winFwACLGroup, "'", "''")
	dnsName := strings.ReplaceAll(winFwDNSUDPRuleName, "'", "''")
	ps := fmt.Sprintf(`
Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'nm-acl-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
`, group, dnsName)
	_, err := runPS(ps)
	return err
}

type netNatEntry struct {
	Name   string
	Prefix string
}

// ensureNetNat makes sure a WinNAT exists for the mesh prefix.
// Windows supports only one internal NetNat prefix system-wide, so foreign NATs
// (Docker/WSL/Hyper-V) are reported clearly instead of the opaque Error 52.
func ensureNetNat(name, internalPrefix string) error {
	prefix := normalizeNetNatPrefix(internalPrefix)
	if prefix == "" {
		return fmt.Errorf("empty NetNat internal prefix")
	}

	entries, err := listAllNetNats()
	if err != nil {
		return fmt.Errorf("list NetNat: %w", err)
	}

	var ours *netNatEntry
	var foreign []netNatEntry
	var staleNetmaker []string
	for i := range entries {
		e := &entries[i]
		switch {
		case e.Name == name:
			ours = e
		case isNetmakerNetNatName(e.Name):
			staleNetmaker = append(staleNetmaker, e.Name)
		default:
			foreign = append(foreign, *e)
		}
	}

	if ours != nil && netNatPrefixesEqual(ours.Prefix, prefix) {
		slog.Debug("windows: NetNat already present", "name", name, "prefix", prefix)
		return nil
	}

	// Foreign WinNAT blocks creation; Error 52 ("duplicate name") is misleading here.
	if len(foreign) > 0 {
		return foreignNetNatConflictError(foreign, name, prefix)
	}

	if ours != nil {
		if err := removeNetNat(ours.Name); err != nil {
			return fmt.Errorf("remove existing NetNat %q: %w", ours.Name, err)
		}
	}
	for _, stale := range staleNetmaker {
		if err := removeNetNat(stale); err != nil {
			slog.Warn("windows: failed removing stale NetNat", "name", stale, "error", err)
		}
	}

	if err := createNetNat(name, prefix); err != nil {
		return wrapNetNatCreateError(err, name, prefix)
	}
	return nil
}

func foreignNetNatConflictError(foreign []netNatEntry, wantName, wantPrefix string) error {
	parts := make([]string, 0, len(foreign))
	for _, e := range foreign {
		p := e.Prefix
		if p == "" {
			p = "unknown prefix"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", e.Name, p))
	}
	return fmt.Errorf("WinNAT already in use by %s; Windows supports only one NetNat — remove the conflicting NAT (often Docker/WSL/Hyper-V) before creating %s for %s",
		strings.Join(parts, ", "), wantName, wantPrefix)
}

func wrapNetNatCreateError(err error, name, prefix string) error {
	msg := err.Error()
	if strings.Contains(msg, "duplicate name") ||
		strings.Contains(msg, "System Error 52") ||
		strings.Contains(msg, "Error 52") {
		return fmt.Errorf("create NetNat %q for %s failed (another WinNAT/HNS NAT likely owns the prefix even if Get-NetNat is empty — check Docker/WSL/Hyper-V or reboot): %w",
			name, prefix, err)
	}
	return fmt.Errorf("create NetNat %q for %s: %w", name, prefix, err)
}

func createNetNat(name, prefix string) error {
	escapedName := strings.ReplaceAll(name, "'", "''")
	escapedPrefix := strings.ReplaceAll(prefix, "'", "''")
	ps := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s' | Out-Null`,
		escapedName, escapedPrefix)
	_, err := runPS(ps)
	return err
}

func removeNetNat(name string) error {
	escapedName := strings.ReplaceAll(name, "'", "''")
	ps := fmt.Sprintf(`$n = Get-NetNat -Name '%s' -ErrorAction SilentlyContinue; if ($null -ne $n) { Remove-NetNat -Name '%s' -Confirm:$false }`, escapedName, escapedName)
	_, err := runPS(ps)
	return err
}

func listAllNetNats() ([]netNatEntry, error) {
	// Use '|' as a delimiter — NetNat names/prefixes do not contain it.
	ps := `Get-NetNat -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}' -f $_.Name, $_.InternalIPInterfaceAddressPrefix }`
	out, err := runPS(ps)
	if err != nil {
		return nil, err
	}
	var entries []netNatEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, prefix, ok := strings.Cut(line, "|")
		if !ok {
			name = line
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		entries = append(entries, netNatEntry{
			Name:   name,
			Prefix: strings.TrimSpace(prefix),
		})
	}
	return entries, nil
}

func listNetmakerNetNats() ([]string, error) {
	entries, err := listAllNetNats()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if isNetmakerNetNatName(e.Name) {
			names = append(names, e.Name)
		}
	}
	return names, nil
}

func runPS(command string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func isIPv4CIDR(cidr string) bool {
	if cidr == ipv4Network || cidr == "*" {
		return true
	}
	if cidr == ipv6Network {
		return false
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	if ip == nil {
		return true
	}
	return ip.To4() != nil
}
