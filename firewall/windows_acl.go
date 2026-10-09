//go:build windows
// +build windows

package firewall

import (
	"fmt"
	"strconv"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/firewall/wfp"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// wfpEngine is the process-wide WFP ACL engine (NetNat remains separate).
var wfpEngine *wfp.Engine

func ensureWFPEngine() error {
	if wfpEngine != nil {
		return nil
	}
	eng, err := wfp.Open()
	if err != nil {
		return err
	}
	wfpEngine = eng
	return nil
}

func closeWFPEngine() {
	if wfpEngine != nil {
		wfpEngine.Close()
		wfpEngine = nil
	}
}

func refreshWFPInterface() error {
	if wfpEngine == nil {
		return nil
	}
	alias := ncutils.GetInterfaceName()
	if err := wfpEngine.SetInterfaceAlias(alias); err != nil {
		slog.Warn("windows: netmaker iface LUID not ready for WFP yet (default deny inactive)",
			"iface", alias, "error", err)
		return err
	}
	return nil
}

// RefreshACLInterface rebinds WFP to the netmaker adapter and installs default
// deny filters. Call after the iface is created — Init often runs too early,
// leaving the ACL layers without their default deny.
func RefreshACLInterface() {
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for ACL iface refresh", "error", err)
		return
	}
	alias := ncutils.GetInterfaceName()
	if err := wfpEngine.SetInterfaceAlias(alias); err != nil {
		slog.Warn("windows: WFP ACL iface bind failed (ACLs not enforced until retry)",
			"iface", alias, "error", err)
		logger.Log(0, "windows: WFP ACL iface bind failed: ", err.Error())
		return
	}
	slog.Debug("windows: WFP ACL bound to netmaker iface", "iface", alias)
}

func ensureWindowsACLBootstrap() {
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: failed to open WFP engine for ACLs", "error", err)
		return
	}
	_ = refreshWFPInterface()
	metricsPort := 0
	if server := config.GetServer(config.CurrServer); server != nil {
		metricsPort = server.MetricsPort
	}
	if err := wfpEngine.EnsureBootstrapAllows(metricsPort); err != nil {
		slog.Warn("windows: failed to install WFP DNS/metrics allows", "error", err)
	}
	// Clean any leftover Defender ACL rules from prior builds.
	_ = removeAllNetmakerACLFirewallRules()
	logger.Log(0, "windows ACL enforcement via WFP (host ALE + IPFORWARD); NetNat unchanged")
}

// ChangeACLInTarget mirrors Linux NETMAKER-ACL-IN default verdict.
func (w *windowsManager) ChangeACLInTarget(target string) {
	slog.Debug("windows: setting ACL input target", "target", target)
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for ACL IN target", "error", err)
		return
	}
	_ = refreshWFPInterface()
	if err := wfpEngine.SetInboundDefaultAccept(target == targetAccept); err != nil {
		slog.Warn("windows: failed to set WFP ACL IN target", "target", target, "error", err)
	}
}

// ChangeACLFwdTarget mirrors Linux NETMAKER-ACL-FWD default verdict via IPFORWARD.
func (w *windowsManager) ChangeACLFwdTarget(target string) {
	slog.Debug("windows: setting ACL forward target", "target", target)
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for ACL FWD target", "error", err)
		return
	}
	_ = refreshWFPInterface()
	if err := wfpEngine.SetForwardDefaultAccept(target == targetAccept); err != nil {
		slog.Warn("windows: failed to set WFP ACL FWD target", "target", target, "error", err)
	}
}

func (w *windowsManager) AddAclRules(server string, aclRules map[string]models.AclRule) {
	ruleTable := w.FetchRuleTable(server, aclTable)
	defer w.SaveRules(server, aclTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	if ruleTable == nil {
		ruleTable = make(ruletable)
	}
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for AddAclRules", "error", err)
		return
	}
	_ = refreshWFPInterface()
	for _, aclRule := range aclRules {
		rules := w.installWFPAclRules(aclRule, wfp.LayerInboundACL)
		if len(rules) == 0 {
			continue
		}
		ruleTable[aclRule.ID] = rulesCfg{
			rulesMap:  map[string][]ruleInfo{aclRule.ID: rules},
			extraInfo: aclRule,
		}
	}
}

func (w *windowsManager) UpsertAclRule(server string, aclRule models.AclRule) {
	ruleTable := w.FetchRuleTable(server, aclTable)
	defer w.SaveRules(server, aclTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	if existing, ok := ruleTable[aclRule.ID]; ok {
		w.removeWFPRules(existing.rulesMap[aclRule.ID])
	}
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for UpsertAclRule", "error", err)
		return
	}
	_ = refreshWFPInterface()
	rules := w.installWFPAclRules(aclRule, wfp.LayerInboundACL)
	if len(rules) == 0 {
		delete(ruleTable, aclRule.ID)
		return
	}
	ruleTable[aclRule.ID] = rulesCfg{
		rulesMap:  map[string][]ruleInfo{aclRule.ID: rules},
		extraInfo: aclRule,
	}
}

func (w *windowsManager) DeleteAclRule(server, aclID string) {
	ruleTable := w.FetchRuleTable(server, aclTable)
	defer w.SaveRules(server, aclTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	cfg, ok := ruleTable[aclID]
	if !ok {
		return
	}
	w.removeWFPRules(cfg.rulesMap[aclID])
	delete(ruleTable, aclID)
}

func (w *windowsManager) AddAclEgressRules(server string, egressInfo models.EgressInfo) {
	ruleTable := w.FetchRuleTable(server, egressTable)
	defer w.SaveRules(server, egressTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	if ruleTable == nil {
		ruleTable = make(ruletable)
	}
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for egress ACLs", "error", err)
		return
	}
	_ = refreshWFPInterface()
	slog.Info("windows: applying egress ACL rules via WFP IPFORWARD",
		"egress", egressInfo.EgressID, "rules", len(egressInfo.EgressFwRules))

	aclRules := egressInfo.EgressFwRules
	rCfg := rulesCfg{rulesMap: make(map[string][]ruleInfo)}
	kept := make(map[string]models.AclRule, len(aclRules))
	for _, aclRule := range aclRules {
		rules := w.installWFPAclRules(aclRule, wfp.LayerForwardACL)
		if len(rules) == 0 {
			slog.Warn("windows: egress ACL produced no WFP filters", "acl", aclRule.ID, "egress", egressInfo.EgressID)
			continue
		}
		rCfg.rulesMap[aclRule.ID] = rules
		kept[aclRule.ID] = aclRule
	}
	rCfg.extraInfo = kept
	ruleTable[fmt.Sprintf("acl#%s", egressInfo.EgressID)] = rCfg
}

func (w *windowsManager) UpsertAclEgressRule(server, egressID string, aclRule models.AclRule) {
	ruleTable := w.FetchRuleTable(server, egressTable)
	defer w.SaveRules(server, egressTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	rCfg := ruleTable[egressID]
	if rCfg.rulesMap == nil {
		rCfg.rulesMap = make(map[string][]ruleInfo)
	}
	extraInfo := map[string]models.AclRule{}
	if rCfg.extraInfo != nil {
		if m, ok := rCfg.extraInfo.(map[string]models.AclRule); ok {
			extraInfo = m
		}
	}
	if old, ok := rCfg.rulesMap[aclRule.ID]; ok {
		w.removeWFPRules(old)
	}
	if err := ensureWFPEngine(); err != nil {
		slog.Warn("windows: WFP unavailable for UpsertAclEgressRule", "error", err)
		return
	}
	_ = refreshWFPInterface()
	rules := w.installWFPAclRules(aclRule, wfp.LayerForwardACL)
	if len(rules) == 0 {
		delete(rCfg.rulesMap, aclRule.ID)
		delete(extraInfo, aclRule.ID)
	} else {
		rCfg.rulesMap[aclRule.ID] = rules
		extraInfo[aclRule.ID] = aclRule
	}
	rCfg.extraInfo = extraInfo
	ruleTable[egressID] = rCfg
}

func (w *windowsManager) DeleteAclEgressRule(server, egressID, aclID string) {
	ruleTable := w.FetchRuleTable(server, egressTable)
	defer w.SaveRules(server, egressTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	rCfg, ok := ruleTable[egressID]
	if !ok {
		return
	}
	w.removeWFPRules(rCfg.rulesMap[aclID])
	delete(rCfg.rulesMap, aclID)
	if rCfg.extraInfo != nil {
		if m, ok := rCfg.extraInfo.(map[string]models.AclRule); ok {
			delete(m, aclID)
			rCfg.extraInfo = m
		}
	}
	ruleTable[egressID] = rCfg
}

func (w *windowsManager) DeleteAllAclEgressRules(server, egressID string) {
	ruleTable := w.FetchRuleTable(server, egressTable)
	defer w.SaveRules(server, egressTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	rCfg, ok := ruleTable[egressID]
	if !ok {
		return
	}
	for _, rules := range rCfg.rulesMap {
		w.removeWFPRules(rules)
	}
	delete(ruleTable, egressID)
}

func (w *windowsManager) installWFPAclRules(acl models.AclRule, layer wfp.Layer) []ruleInfo {
	if wfpEngine == nil {
		return nil
	}
	specs := aclToFilterSpecs(acl, int(layer))
	var rules []ruleInfo
	for _, spec := range specs {
		ids, err := wfpEngine.AddAllow(wfp.FilterSpec{
			Name:       spec.Name,
			Layer:      wfp.Layer(spec.Layer),
			SrcNets:    spec.SrcNets,
			DstNets:    spec.DstNets,
			Protocol:   spec.Protocol,
			DstPort:    spec.DstPort,
			DstPortMax: spec.DstPortMax,
		})
		if err != nil {
			slog.Warn("windows: failed to add WFP ACL filter",
				"acl", acl.ID, "name", spec.Name, "layer", layer, "error", err)
			continue
		}
		for _, id := range ids {
			rules = append(rules, ruleInfo{
				rule:  []string{"wfp", fmt.Sprintf("%d", id)},
				table: "windows",
				chain: fmt.Sprintf("wfp-%d", layer),
			})
		}
	}
	return rules
}

func (w *windowsManager) removeWFPRules(rules []ruleInfo) {
	if wfpEngine == nil {
		return
	}
	var ids []uint64
	for _, rule := range rules {
		if len(rule.rule) < 2 {
			continue
		}
		switch rule.rule[0] {
		case "wfp":
			id, err := strconv.ParseUint(rule.rule[1], 10, 64)
			if err == nil {
				ids = append(ids, id)
			}
		case "winfw":
			// Legacy Defender ACL rule from prior builds.
			_ = removeWindowsFirewallRule(rule.rule[1])
		}
	}
	wfpEngine.DeleteFilters(ids)
}
