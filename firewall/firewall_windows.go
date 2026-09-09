//go:build windows
// +build windows

package firewall

import (
	"fmt"
	"net"
	"os/exec"
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
)

// windowsManager implements Direct NAT egress via Hyper-V NetNat + IP forwarding.
// ACL / FORWARD filtering is best-effort in v1 (server ACLs still gate who receives routes).
type windowsManager struct {
	mux          sync.Mutex
	engressRules serverrulestable
	ingRules     serverrulestable
	aclRules     serverrulestable
}

func newFirewall() (firewallController, error) {
	logger.Log(0, "using Windows NetNat to manage egress NAT rules...")
	slog.Warn("windows egress ACL filtering is not enforced in v1; only Direct NAT + IP forwarding are applied")
	if cfg := config.Netclient(); cfg != nil {
		cfg.FirewallInUse = schema.FIREWALL_NETNAT
	}
	return &windowsManager{
		engressRules: make(serverrulestable),
		ingRules:     make(serverrulestable),
		aclRules:     make(serverrulestable),
	}, nil
}

func (w *windowsManager) CreateChains() error { return nil }
func (w *windowsManager) ForwardRule() error  { return nil }
func (w *windowsManager) AddDropRules([]ruleInfo) {
}
func (w *windowsManager) ChangeACLInTarget(string)  {}
func (w *windowsManager) ChangeACLFwdTarget(string) {}

func (w *windowsManager) InsertIngressRoutingRules(server string, ingressInfo models.IngressInfo) error {
	return nil
}

func (w *windowsManager) AddAclRules(server string, aclRules map[string]models.AclRule) {}
func (w *windowsManager) UpsertAclRule(server string, aclRule models.AclRule)           {}
func (w *windowsManager) DeleteAclRule(server, aclID string)                             {}

func (w *windowsManager) AddAclEgressRules(server string, egressInfo models.EgressInfo) {
	slog.Debug("windows: skipping egress ACL rules (v1)", "egress", egressInfo.EgressID)
}
func (w *windowsManager) DeleteAclEgressRule(server, nodeID, aclID string)                  {}
func (w *windowsManager) UpsertAclEgressRule(server, nodeID string, aclRule models.AclRule) {}
func (w *windowsManager) DeleteAllAclEgressRules(server, egressID string)                   {}

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
		meshPrefix := egressInfo.Network.String()
		if !isIPv4CIDR(egressGwRange.Network) && egressInfo.Network6.IP != nil {
			meshPrefix = egressInfo.Network6.String()
		}
		if meshPrefix == "" || meshPrefix == "<nil>" {
			slog.Warn("windows: missing mesh network prefix for NetNat", "egress", egressInfo.EgressID)
			continue
		}
		name := netNatName(egressInfo.EgressID)
		if err := ensureNetNat(name, meshPrefix); err != nil {
			slog.Error("windows: failed to create NetNat for egress",
				"egress", egressInfo.EgressID, "name", name, "prefix", meshPrefix, "error", err)
			return fmt.Errorf("NetNat create failed (is Hyper-V / NetNat available?): %w", err)
		}
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
			if len(rule.rule) >= 2 && rule.rule[0] == "netnat" {
				_ = removeNetNat(rule.rule[1])
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
	slog.Info("windows: flushing netmaker NetNat rules")
	names, err := listNetmakerNetNats()
	if err != nil {
		slog.Warn("windows: failed listing NetNats during flush", "error", err)
		return
	}
	for _, name := range names {
		if err := removeNetNat(name); err != nil {
			slog.Warn("windows: failed removing NetNat", "name", name, "error", err)
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

func ensureNetNat(name, internalPrefix string) error {
	escapedName := strings.ReplaceAll(name, "'", "''")
	escapedPrefix := strings.ReplaceAll(internalPrefix, "'", "''")
	// Remove existing NetNat with same name to avoid prefix conflicts, then create.
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$name = '%s'
$prefix = '%s'
$existing = Get-NetNat -Name $name -ErrorAction SilentlyContinue
if ($null -ne $existing) {
  Remove-NetNat -Name $name -Confirm:$false
}
New-NetNat -Name $name -InternalIPInterfaceAddressPrefix $prefix | Out-Null
`, escapedName, escapedPrefix)
	_, err := runPS(ps)
	return err
}

func removeNetNat(name string) error {
	escapedName := strings.ReplaceAll(name, "'", "''")
	ps := fmt.Sprintf(`$n = Get-NetNat -Name '%s' -ErrorAction SilentlyContinue; if ($null -ne $n) { Remove-NetNat -Name '%s' -Confirm:$false }`, escapedName, escapedName)
	_, err := runPS(ps)
	return err
}

func listNetmakerNetNats() ([]string, error) {
	ps := `Get-NetNat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name`
	out, err := runPS(ps)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if isNetmakerNetNatName(name) {
			names = append(names, name)
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
