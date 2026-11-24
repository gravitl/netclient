//go:build windows
// +build windows

package firewall

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/firewall/wfp"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// wfpEngine is the process-wide WFP ACL engine (NetNat remains separate).
// wfpMu serializes open/close/use: soft-restart FlushAll races MQTT peer
// updates that still call ChangeACL* / AddAcl*.
var (
	wfpEngine *wfp.Engine
	wfpMu     sync.Mutex
)

// defenderACLCleanupOnce removes leftover Defender Firewall ACL rules from the
// pre-WFP implementation at most once per process. Init used to pay for this
// three times (FlushAll + CreateChains + ForwardRule), each spawning PowerShell.
var (
	defenderACLCleanupOnce sync.Once
	aclBootstrapLogOnce    sync.Once
)

// withWFPEngine runs fn against a live engine. Holds wfpMu for the whole call
// so closeWFPEngine cannot nil the pointer mid-use.
func withWFPEngine(fn func(*wfp.Engine) error) error {
	wfpMu.Lock()
	defer wfpMu.Unlock()
	if wfpEngine == nil {
		eng, err := wfp.Open()
		if err != nil {
			return err
		}
		wfpEngine = eng
	}
	return fn(wfpEngine)
}

func closeWFPEngine() {
	wfpMu.Lock()
	defer wfpMu.Unlock()
	if wfpEngine != nil {
		wfpEngine.Close()
		wfpEngine = nil
	}
}

// deleteWFPFiltersIfOpen drops filters when an engine is already open.
// Does not open a new session (cleanup after FlushAll must stay a no-op).
func deleteWFPFiltersIfOpen(ids []uint64) {
	if len(ids) == 0 {
		return
	}
	wfpMu.Lock()
	defer wfpMu.Unlock()
	if wfpEngine != nil {
		wfpEngine.DeleteFilters(ids)
	}
}

func refreshWFPInterfaceLocked(eng *wfp.Engine) error {
	alias := ncutils.GetInterfaceName()
	if err := eng.SetInterfaceAlias(alias); err != nil {
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
	alias := ncutils.GetInterfaceName()
	if err := withWFPEngine(func(eng *wfp.Engine) error {
		return eng.SetInterfaceAlias(alias)
	}); err != nil {
		slog.Warn("windows: WFP ACL iface bind failed (ACLs not enforced until retry)",
			"iface", alias, "error", err)
		logger.Log(0, "windows: WFP ACL iface bind failed: ", err.Error())
		return
	}
	slog.Debug("windows: WFP ACL bound to netmaker iface", "iface", alias)
}

func ensureWindowsACLBootstrap() {
	start := time.Now()
	metricsPort := 0
	if server := config.GetServer(config.CurrServer); server != nil {
		metricsPort = server.MetricsPort
	}
	if err := withWFPEngine(func(eng *wfp.Engine) error {
		_ = refreshWFPInterfaceLocked(eng)
		return eng.EnsureBootstrapAllows(metricsPort)
	}); err != nil {
		slog.Warn("windows: failed to open/bootstrap WFP engine for ACLs", "error", err)
		return
	}
	cleanupLegacyDefenderACLRules()
	aclBootstrapLogOnce.Do(func() {
		logger.Log(0, "windows ACL enforcement via WFP (host ALE + IPFORWARD); NetNat unchanged")
	})
	if d := time.Since(start); d > 500*time.Millisecond {
		logger.Log(0, "windows ACL bootstrap took ", d.String())
	}
}

// cleanupLegacyDefenderACLRules runs the Defender→WFP migration cleanup once.
func cleanupLegacyDefenderACLRules() {
	defenderACLCleanupOnce.Do(func() {
		start := time.Now()
		if err := removeAllNetmakerACLFirewallRules(); err != nil {
			slog.Warn("windows: failed removing leftover Defender ACL rules", "error", err)
		}
		if d := time.Since(start); d > 500*time.Millisecond {
			logger.Log(0, "windows legacy Defender ACL cleanup took ", d.String())
		}
	})
}

// ChangeACLInTarget mirrors Linux NETMAKER-ACL-IN default verdict.
func (w *windowsManager) ChangeACLInTarget(target string) {
	slog.Debug("windows: setting ACL input target", "target", target)
	if err := withWFPEngine(func(eng *wfp.Engine) error {
		_ = refreshWFPInterfaceLocked(eng)
		return eng.SetInboundDefaultAccept(target == targetAccept)
	}); err != nil {
		slog.Warn("windows: failed to set WFP ACL IN target", "target", target, "error", err)
	}
}

// ChangeACLFwdTarget mirrors Linux NETMAKER-ACL-FWD default verdict via IPFORWARD.
func (w *windowsManager) ChangeACLFwdTarget(target string) {
	slog.Debug("windows: setting ACL forward target", "target", target)
	if err := withWFPEngine(func(eng *wfp.Engine) error {
		_ = refreshWFPInterfaceLocked(eng)
		return eng.SetForwardDefaultAccept(target == targetAccept)
	}); err != nil {
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
	err := withWFPEngine(func(eng *wfp.Engine) error {
		_ = refreshWFPInterfaceLocked(eng)
		for _, aclRule := range aclRules {
			rules := w.installWFPAclRules(eng, aclRule, wfp.LayerInboundACL)
			if len(rules) == 0 {
				continue
			}
			ruleTable[aclRule.ID] = rulesCfg{
				rulesMap:  map[string][]ruleInfo{aclRule.ID: rules},
				extraInfo: aclRule,
			}
		}
		return nil
	})
	if err != nil {
		slog.Warn("windows: WFP unavailable for AddAclRules", "error", err)
	}
}

func (w *windowsManager) UpsertAclRule(server string, aclRule models.AclRule) {
	ruleTable := w.FetchRuleTable(server, aclTable)
	defer w.SaveRules(server, aclTable, ruleTable)
	w.mux.Lock()
	defer w.mux.Unlock()
	err := withWFPEngine(func(eng *wfp.Engine) error {
		if existing, ok := ruleTable[aclRule.ID]; ok {
			w.removeWFPRules(eng, existing.rulesMap[aclRule.ID])
		}
		_ = refreshWFPInterfaceLocked(eng)
		rules := w.installWFPAclRules(eng, aclRule, wfp.LayerInboundACL)
		if len(rules) == 0 {
			delete(ruleTable, aclRule.ID)
			return nil
		}
		ruleTable[aclRule.ID] = rulesCfg{
			rulesMap:  map[string][]ruleInfo{aclRule.ID: rules},
			extraInfo: aclRule,
		}
		return nil
	})
	if err != nil {
		slog.Warn("windows: WFP unavailable for UpsertAclRule", "error", err)
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
	_ = withWFPEngine(func(eng *wfp.Engine) error {
		w.removeWFPRules(eng, cfg.rulesMap[aclID])
		return nil
	})
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
	err := withWFPEngine(func(eng *wfp.Engine) error {
		_ = refreshWFPInterfaceLocked(eng)
		slog.Info("windows: applying egress ACL rules via WFP IPFORWARD",
			"egress", egressInfo.EgressID, "rules", len(egressInfo.EgressFwRules))

		aclRules := egressInfo.EgressFwRules
		rCfg := rulesCfg{rulesMap: make(map[string][]ruleInfo)}
		kept := make(map[string]models.AclRule, len(aclRules))
		for _, aclRule := range aclRules {
			rules := w.installWFPAclRules(eng, aclRule, wfp.LayerForwardACL)
			if len(rules) == 0 {
				slog.Warn("windows: egress ACL produced no WFP filters", "acl", aclRule.ID, "egress", egressInfo.EgressID)
				continue
			}
			rCfg.rulesMap[aclRule.ID] = rules
			kept[aclRule.ID] = aclRule
		}
		rCfg.extraInfo = kept
		ruleTable[fmt.Sprintf("acl#%s", egressInfo.EgressID)] = rCfg
		return nil
	})
	if err != nil {
		slog.Warn("windows: WFP unavailable for egress ACLs", "error", err)
	}
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
	err := withWFPEngine(func(eng *wfp.Engine) error {
		if old, ok := rCfg.rulesMap[aclRule.ID]; ok {
			w.removeWFPRules(eng, old)
		}
		_ = refreshWFPInterfaceLocked(eng)
		rules := w.installWFPAclRules(eng, aclRule, wfp.LayerForwardACL)
		if len(rules) == 0 {
			delete(rCfg.rulesMap, aclRule.ID)
			delete(extraInfo, aclRule.ID)
		} else {
			rCfg.rulesMap[aclRule.ID] = rules
			extraInfo[aclRule.ID] = aclRule
		}
		return nil
	})
	if err != nil {
		slog.Warn("windows: WFP unavailable for UpsertAclEgressRule", "error", err)
		return
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
	_ = withWFPEngine(func(eng *wfp.Engine) error {
		w.removeWFPRules(eng, rCfg.rulesMap[aclID])
		return nil
	})
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
	_ = withWFPEngine(func(eng *wfp.Engine) error {
		for _, rules := range rCfg.rulesMap {
			w.removeWFPRules(eng, rules)
		}
		return nil
	})
	delete(ruleTable, egressID)
}

// installWFPAclRules must be called under wfpMu (via withWFPEngine).
func (w *windowsManager) installWFPAclRules(eng *wfp.Engine, acl models.AclRule, layer wfp.Layer) []ruleInfo {
	if eng == nil {
		return nil
	}
	specs := aclToFilterSpecs(acl, int(layer))
	var rules []ruleInfo
	for _, spec := range specs {
		ids, err := eng.AddAllow(wfp.FilterSpec{
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

// removeWFPRules must be called under wfpMu (via withWFPEngine).
func (w *windowsManager) removeWFPRules(eng *wfp.Engine, rules []ruleInfo) {
	if eng == nil {
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
	eng.DeleteFilters(ids)
}
