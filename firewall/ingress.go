package firewall

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

func ProcessIngressUpdate(server string, ingressUpdate map[string]models.IngressInfo) error {
	if fwCrtl == nil {
		return errors.New("firewall is not initialized yet")
	}
	fmt.Printf("INGRESS---UPDTE: %+v\n", ingressUpdate)
	ruleTable := fwCrtl.FetchRuleTable(server, ingressTable)
	for nodeID := range ruleTable {
		if _, ok := ingressUpdate[nodeID]; !ok {
			// node is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, ingressTable, nodeID)
		}
	}
	for nodeID, ingressInfo := range ingressUpdate {
		rules, ok := ruleTable[nodeID]
		if !ok {
			// set up rules for the ingress GW on first time creation
			fwCrtl.InsertIngressRoutingRules(server, ingressInfo)
			slog.Info("setting ingress routes", "network", nodeID)
			continue
		} else {
			oldIngressinfo := rules.extraInfo.(models.IngressInfo)
			if (len(oldIngressinfo.StaticNodeIps) != len(ingressInfo.StaticNodeIps)) ||
				(!reflect.DeepEqual(oldIngressinfo.StaticNodeIps, ingressInfo.StaticNodeIps)) ||
				(len(oldIngressinfo.Rules) != len(ingressInfo.Rules)) ||
				(!reflect.DeepEqual(oldIngressinfo.Rules, ingressInfo.Rules)) {
				// refresh the rules
				fwCrtl.RemoveRoutingRules(server, ingressTable, nodeID)
				// set up rules for the ingress GW on first time creation
				fwCrtl.InsertIngressRoutingRules(server, ingressInfo)
			}
		}
	}

	return nil
}

func RemoveIngressRoutingRules(server string) {
	if fwCrtl == nil {
		return
	}
	fwCrtl.CleanRoutingRules(server, egressTable)
}
