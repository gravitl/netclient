package firewall

import (
	"errors"
	"reflect"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

func processEgressFwRules(server string, egressUpdate map[string]models.EgressInfo) {

	for _, egressInfoI := range egressUpdate {
		aclRules := egressInfoI.EgressFwRules
		ruleTable := fwCrtl.FetchRuleTable(server, egressTable)
		if len(ruleTable) == 0 && len(aclRules) > 0 {
			fwCrtl.AddAclEgressRules(server, aclRules)
			return
		}
		// add new acl rules
		for _, aclRule := range aclRules {
			if _, ok := ruleTable[aclRule.ID]; !ok {
				fwCrtl.UpsertAclEgressRule(server, aclRule)
			} else {
				// check if there is a update
				ruleCfg := ruleTable[aclRule.ID]
				var localAclRule models.AclRule
				if ruleCfg.extraInfo != nil {
					localAclRule = ruleCfg.extraInfo.(models.AclRule)
				}
				if (len(localAclRule.IPList) != len(aclRule.IPList)) ||
					(!reflect.DeepEqual(localAclRule.IPList, aclRule.IPList)) ||
					(len(localAclRule.IP6List) != len(aclRule.IP6List)) ||
					(!reflect.DeepEqual(localAclRule.IP6List, aclRule.IP6List)) ||
					(len(localAclRule.AllowedPorts) != len(aclRule.AllowedPorts)) ||
					(!reflect.DeepEqual(localAclRule.AllowedPorts, aclRule.AllowedPorts)) ||
					(aclRule.AllowedProtocol != localAclRule.AllowedProtocol) ||
					(localAclRule.Direction != aclRule.Direction) ||
					(localAclRule.Dst.String() != aclRule.Dst.String()) ||
					(localAclRule.Dst6.String() != aclRule.Dst6.String()) {
					fwCrtl.DeleteAclEgressRule(server, aclRule.ID)
					fwCrtl.UpsertAclEgressRule(server, aclRule)
				}
			}
		}
		// check if any rules needs to be deleted
		for aclID := range ruleTable {
			if _, ok := aclRules[aclID]; !ok {
				fwCrtl.DeleteAclEgressRule(server, aclID)
			}
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
		if _, ok := ruleTable[egressNodeID]; !ok {
			// set up rules for the GW on first time creation
			slog.Info("setting egress routes", "node", egressNodeID)
			fwCrtl.InsertEgressRoutingRules(server, egressInfo)
			continue
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
