package firewall

import (
	"fmt"
	"reflect"

	"github.com/gravitl/netmaker/models"
)

func ProcessAclRules(server string, fwUpdate *models.FwUpdate) {
	if fwCrtl == nil {
		return
	}
	if fwUpdate.AllowAll {
		fwCrtl.ChangeACLTarget(targetAccept)
	} else {
		fwCrtl.ChangeACLTarget(targetDrop)
	}

	aclRules := fwUpdate.AclRules
	ruleTable := fwCrtl.FetchRuleTable(server, aclTable)
	fmt.Printf("======> ACL RULES: %+v\n, Curr Rule table: %+v\n", fwUpdate.AclRules, ruleTable)
	if len(ruleTable) == 0 && len(aclRules) > 0 {
		fwCrtl.AddAclRules(server, aclRules)
		ruleTable := fwCrtl.FetchRuleTable(server, aclTable)
		fmt.Printf("======> AFTER ACL RULES: Curr Rule table: %+v\n", ruleTable)
		return
	}
	fmt.Println("## CHECKING New RULES==>")
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
				(aclRule.AllowedProtocols != localAclRule.AllowedProtocols) ||
				(localAclRule.Direction) != aclRule.Direction {
				fwCrtl.DeleteAclRule(server, aclRule.ID)
				fwCrtl.UpsertAclRule(server, aclRule)
			}
		}
	}
	// check if any rules needs to be deleted
	for aclID := range ruleTable {
		if _, ok := aclRules[aclID]; !ok {
			fwCrtl.DeleteAclRule(server, aclID)
		}
	}
}
