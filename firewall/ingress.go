package firewall

import (
	"errors"
	"reflect"
	"strings"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

func ProcessIngressUpdate(server string, ingressUpdate map[string]models.IngressInfo) error {
	return restrictUserToUserComms(server, ingressUpdate)
}

func restrictUserToUserComms(server string, ingressUpdate map[string]models.IngressInfo) error {
	if fwCrtl == nil {
		return errors.New("firewall is not initialized yet")
	}
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
			fwCrtl.RestrictUserToUserComms(server, ingressInfo)
			slog.Info("setting ingress routes", "network", nodeID)
			continue
		} else {
			rulesInfo := rules.rulesMap[nodeID]
			ips := []string{}
			for _, ruleI := range rulesInfo {
				if len(ruleI.rule) > 1 {
					ips = append(ips, strings.Split(ruleI.rule[1], ",")...)
				}
			}
			if (len(ips) != len(ingressInfo.UserIps)) ||
				(!reflect.DeepEqual(ips, ingressInfo.UserIps)) {
				// refresh the rules
				fwCrtl.RemoveRoutingRules(server, ingressTable, nodeID)
				// set up rules for the ingress GW on first time creation
				fwCrtl.RestrictUserToUserComms(server, ingressInfo)
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
