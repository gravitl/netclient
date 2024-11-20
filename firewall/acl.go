package firewall

import (
	"reflect"

	"github.com/gravitl/netmaker/models"
)

func ProcessAclRules(server string, aclRules map[string]models.AclRule) {
	if fwCrtl == nil {
		return
	}
	ruleTable := fwCrtl.FetchRuleTable(server, aclTable)
	if len(ruleTable) == 0 && len(aclRules) > 0 {
		fwCrtl.AddAclRules(server, aclRules)
		return
	}
	// add new acl rules
	for _, aclRule := range aclRules {
		if _, ok := ruleTable[aclRule.ID]; !ok {
			fwCrtl.UpsertAclRule(server, aclRule)
		} else {
			// check if there is a update
			ruleCfg := ruleTable[aclRule.ID]
			localAclRule := ruleCfg.extraInfo.(models.AclRule)
			if (len(localAclRule.IPList) != len(aclRule.IPList)) ||
				(!reflect.DeepEqual(localAclRule.IPList, aclRule.IPList)) ||
				(len(localAclRule.IP6List) != len(aclRule.IP6List)) ||
				(!reflect.DeepEqual(localAclRule.IP6List, aclRule.IP6List)) ||
				(len(localAclRule.AllowedPorts) != len(aclRule.AllowedPorts)) ||
				(!reflect.DeepEqual(localAclRule.AllowedPorts, aclRule.AllowedPorts)) ||
				(localAclRule.Direction) != aclRule.Direction {
				fwCrtl.DeleteAclRule(server, aclRule.ID)
				fwCrtl.UpsertAclRule(server, aclRule)
			}
		}
	}
}
