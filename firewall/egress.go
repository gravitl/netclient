package firewall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

func processEgressFwRules(server string, egressUpdate map[string]models.EgressInfo) {
	ruleTable := fwCrtl.FetchRuleTable(server, egressTable)
	if isEgressAclRulesEqual(ruleTable, egressUpdate) {
		return
	}
	// Anything changed: reinstall the ACL entries like a fresh install does. nftables keeps
	// one kernel rule per generated spec, shared by every ACL rule with the same source,
	// protocol, port and destination, so reconciling single rules in place can remove a rule
	// another entry still needs. That sharing is #1419; once every egress ACL has its own rule
	// (#1437), changed rules can be reconciled one by one again.
	for egressID := range ruleTable {
		if strings.HasPrefix(egressID, "acl#") {
			fwCrtl.DeleteAllAclEgressRules(server, egressID)
		}
	}
	for _, egressInfo := range egressUpdate {
		fwCrtl.AddAclEgressRules(server, egressInfo)
	}
}

// isEgressAclRulesEqual reports whether the stored egress ACL entries already match the update.
func isEgressAclRulesEqual(ruleTable ruletable, egressUpdate map[string]models.EgressInfo) bool {
	aclEntries := make(map[string]bool, len(egressUpdate))
	for _, egressInfo := range egressUpdate {
		egressAclID := fmt.Sprintf("acl#%s", egressInfo.EgressID)
		aclEntries[egressAclID] = true
		ruleCfg, ok := ruleTable[egressAclID]
		if !ok {
			return false
		}
		localAclRules, _ := ruleCfg.extraInfo.(map[string]models.AclRule)
		if len(localAclRules) != len(egressInfo.EgressFwRules) {
			return false
		}
		for aclID, aclRule := range egressInfo.EgressFwRules {
			localAclRule, ok := localAclRules[aclID]
			if !ok || !isAclRuleEqual(localAclRule, aclRule) {
				return false
			}
		}
	}
	for egressAclID := range ruleTable {
		if strings.HasPrefix(egressAclID, "acl#") && !aclEntries[egressAclID] {
			return false
		}
	}
	return true
}

func isAclRuleEqual(a, b models.AclRule) bool {
	return reflect.DeepEqual(a.IPList, b.IPList) &&
		reflect.DeepEqual(a.IP6List, b.IP6List) &&
		reflect.DeepEqual(a.AllowedPorts, b.AllowedPorts) &&
		a.AllowedProtocol == b.AllowedProtocol &&
		a.Direction == b.Direction &&
		reflect.DeepEqual(a.Dst, b.Dst) &&
		reflect.DeepEqual(a.Dst6, b.Dst6)
}

// SetEgressRoutes - sets the egress route for the gateway
func SetEgressRoutes(server string, egressUpdate map[string]models.EgressInfo) error {
	fwMutex.Lock()
	defer fwMutex.Unlock()
	if fwCrtl == nil {
		return errors.New("firewall is not initialized yet")
	}
	ruleTable := fwCrtl.FetchRuleTable(server, egressTable)
	for egressNodeID := range ruleTable {
		// egress ACL entries are keyed "acl#<egress ID>" and are reconciled by processEgressFwRules
		if strings.HasPrefix(egressNodeID, "acl#") {
			continue
		}
		if _, ok := egressUpdate[egressNodeID]; !ok {
			// egress GW is deleted, flush out all rules
			slog.Info("removing egress routes for deleted node", "node", egressNodeID)
			fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
		}
	}
	for egressNodeID, egressInfo := range egressUpdate {
		if existingRules, ok := ruleTable[egressNodeID]; !ok {
			// set up rules for the GW on first time creation
			slog.Info("setting egress routes", "node", egressNodeID)
			fwCrtl.InsertEgressRoutingRules(server, egressInfo)
			continue
		} else {
			egressGatewayReq := existingRules.extraInfo.(models.EgressGatewayRequest)
			rangesEqual := isEgressRangeEqual(egressGatewayReq.RangesWithMetric, egressInfo.EgressGWCfg.RangesWithMetric)
			slog.Info("checking egress range equality", "node", egressNodeID, "rangesEqual", rangesEqual)
			if !rangesEqual {
				slog.Info("egress ranges changed, removing old rules and inserting new ones", "node", egressNodeID)
				// Log the differences for debugging
				for i, oldRange := range egressGatewayReq.RangesWithMetric {
					if i < len(egressInfo.EgressGWCfg.RangesWithMetric) {
						newRange := egressInfo.EgressGWCfg.RangesWithMetric[i]
						slog.Info("range comparison", "index", i,
							"old_network", oldRange.Network, "old_nat", oldRange.Nat, "old_mode", oldRange.Mode, "old_virtualNetwork", oldRange.VirtualNetwork,
							"new_network", newRange.Network, "new_nat", newRange.Nat, "new_mode", newRange.Mode, "new_virtualNetwork", newRange.VirtualNetwork)
					}
				}
				// egress GW is deleted, flush out all rules
				fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
				fwCrtl.InsertEgressRoutingRules(server, egressInfo)
			} else {
				slog.Debug("egress ranges unchanged, skipping update", "node", egressNodeID)
			}
		}
	}
	processEgressFwRules(server, egressUpdate)
	return nil
}

// DeleteEgressGwRoutes - deletes egress routes for the gateway
func DeleteEgressGwRoutes(server string) {
	if fwCrtl == nil {
		return
	}
	fwCrtl.CleanRoutingRules(server, egressTable)
}

func key(e models.EgressRangeMetric) string {
	// Include VirtualNetwork and Mode in the key to detect changes when switching between
	// direct NAT, virtual NAT with different networks, or different virtual networks
	virtualNetwork := e.VirtualNetwork
	if virtualNetwork == "" {
		virtualNetwork = "direct"
	}
	return fmt.Sprintf("%s|%t|%s|%s", e.Network, e.Nat, e.Mode, virtualNetwork)
}

func isEgressRangeEqual(a, b []models.EgressRangeMetric) bool {
	if len(a) != len(b) {
		return false
	}

	counts := make(map[string]int)
	for _, e := range a {
		counts[key(e)]++
	}
	for _, e := range b {
		k := key(e)
		if counts[k] == 0 {
			return false
		}
		counts[k]--
	}
	return true
}
