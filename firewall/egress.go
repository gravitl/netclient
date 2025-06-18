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
	for _, egressInfoI := range egressUpdate {
		aclRules := egressInfoI.EgressFwRules
		egressAclID := fmt.Sprintf("acl#%s", egressInfoI.EgressID)
		egressRules, ok := ruleTable[egressAclID]
		if !ok {
			fwCrtl.AddAclEgressRules(server, egressInfoI)
			continue
		}
		ruleCfg := ruleTable[egressAclID]
		// check if there is a update
		localAclRules := make(map[string]models.AclRule)
		if ruleCfg.extraInfo != nil {
			localAclRules = ruleCfg.extraInfo.(map[string]models.AclRule)
		}
		// add new acl rules
		for _, aclRule := range aclRules {
			if _, ok := ruleTable[egressAclID].rulesMap[aclRule.ID]; !ok {
				fwCrtl.UpsertAclEgressRule(server, egressAclID, aclRule)
			} else {
				localAclRule := localAclRules[aclRule.ID]
				if (len(localAclRule.IPList) != len(aclRule.IPList)) ||
					(!reflect.DeepEqual(localAclRule.IPList, aclRule.IPList)) ||
					(len(localAclRule.IP6List) != len(aclRule.IP6List)) ||
					(!reflect.DeepEqual(localAclRule.IP6List, aclRule.IP6List)) ||
					(len(localAclRule.AllowedPorts) != len(aclRule.AllowedPorts)) ||
					(!reflect.DeepEqual(localAclRule.AllowedPorts, aclRule.AllowedPorts)) ||
					(aclRule.AllowedProtocol != localAclRule.AllowedProtocol) ||
					(localAclRule.Direction != aclRule.Direction) ||
					(!reflect.DeepEqual(localAclRule.Dst, aclRule.Dst)) ||
					(len(localAclRule.Dst6) != len(aclRule.Dst6)) {
					fwCrtl.DeleteAclEgressRule(server, egressAclID, aclRule.ID)
					fwCrtl.UpsertAclEgressRule(server, egressAclID, aclRule)
				}
			}
		}
		// check if any rules needs to be deleted
		for aclID := range egressRules.rulesMap {
			if _, ok := aclRules[aclID]; !ok {
				fwCrtl.DeleteAclEgressRule(server, egressAclID, aclID)
			}
		}
	}
	ruleTable = fwCrtl.FetchRuleTable(server, egressTable)
	for egressID := range ruleTable {
		if !strings.Contains(egressID, "acl#") {
			continue
		}
		id := strings.Split(egressID, "#")[1]
		if _, ok := egressUpdate[id]; !ok {
			fwCrtl.DeleteAllAclEgressRules(server, egressID)
		}
	}

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
		if _, ok := egressUpdate[egressNodeID]; !ok {
			// egress GW is deleted, flush out all rules
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
			if !isEgressRangeEqual(egressGatewayReq.RangesWithMetric, egressInfo.EgressGWCfg.RangesWithMetric) {
				// egress GW is deleted, flush out all rules
				fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
				fwCrtl.InsertEgressRoutingRules(server, egressInfo)
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
	return fmt.Sprintf("%s|%t", e.Network, e.Nat)
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
