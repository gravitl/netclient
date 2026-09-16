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
	for _, rules := range cfg.rulesMap {
		for _, rule := range rules {
			if len(rule.rule) < 2 {
				continue
			}
			switch rule.rule[0] {
			case "netnat":
				_ = removeNetNat(rule.rule[1])
			case "wfp":
				if wfpEngine != nil {
					if id, err := strconv.ParseUint(rule.rule[1], 10, 64); err == nil {
						wfpEngine.DeleteFilters([]uint64{id})
					}
				}
			case "winfw":
				_ = removeWindowsFirewallRule(rule.rule[1])
			}
		}
	}
	delete(rulesTable, peerKey)
	return nil
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
	slog.Info("windows: flushing netmaker NetNat and WFP ACL filters")
	closeWFPEngine()
	if err := removeAllNetmakerACLFirewallRules(); err != nil {
		slog.Warn("windows: failed removing leftover Defender ACL rules", "error", err)
	}
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
}

func getWindowsInterfaceName(dstCIDR string) (string, error) {
	ip := dstCIDR
	if dstCIDR == ipv4Network || dstCIDR == ipv6Network || dstCIDR == "*" {
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
func removeAllNetmakerACLFirewallRules() error {
	ps := fmt.Sprintf(`
Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -like 'nm-acl-*' -or $_.Name -eq '%s'
} | Remove-NetFirewallRule -ErrorAction SilentlyContinue
`, strings.ReplaceAll(winFwACLGroup, "'", "''"), strings.ReplaceAll(winFwDNSUDPRuleName, "'", "''"))
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
