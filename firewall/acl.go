package firewall

import (
	"fmt"
	"reflect"

	"github.com/gravitl/netmaker/models"
)

func ProcessAclRules(server string, fwUpdate *models.FwUpdate) {
	fmt.Println("================> PROCESSING ACL RULES")
	fwMutex.Lock()
	defer fwMutex.Unlock()
	if fwCrtl == nil {
		return
	}
	if fwUpdate.AllowAll {
		fwCrtl.ChangeACLInTarget(targetAccept)
		fwCrtl.ChangeACLFwdTarget(targetAccept)
	} else {
		fwCrtl.ChangeACLInTarget(targetDrop)
		fwCrtl.ChangeACLFwdTarget(targetDrop)
	}

	aclRules := fwUpdate.AclRules
	ruleTable := fwCrtl.FetchRuleTable(server, aclTable)
	if len(ruleTable) == 0 && len(aclRules) > 0 {
		fmt.Println("================> PROCESSING ACL RULES   1")
		fwCrtl.AddAclRules(server, aclRules)
		return
	}
	// add new acl rules
	for _, aclRule := range aclRules {
		if _, ok := ruleTable[aclRule.ID]; !ok {
			fmt.Println("================> PROCESSING ACL RULES   2")
			fwCrtl.UpsertAclRule(server, aclRule)
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
				(localAclRule.Direction != aclRule.Direction) {
				fwCrtl.DeleteAclRule(server, aclRule.ID)
				fwCrtl.UpsertAclRule(server, aclRule)
				fmt.Println("================> PROCESSING ACL RULES   3")
			}
		}
	}
	// check if any rules needs to be deleted
	for aclID := range ruleTable {
		if _, ok := aclRules[aclID]; !ok {
			fwCrtl.DeleteAclRule(server, aclID)
			fmt.Println("================> PROCESSING ACL RULES   4")
		}
	}
}
