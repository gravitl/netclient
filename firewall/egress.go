package firewall

import (
	"errors"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// SetEgressRoutes - sets the egress route for the gateway
func SetEgressRoutes(server string, egressUpdate map[string]models.EgressInfo) error {
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
	return nil
}

// DeleteEgressGwRoutes - deletes egress routes for the gateway
func DeleteEgressGwRoutes(server string) {
	if fwCrtl == nil {
		return
	}
	fwCrtl.CleanRoutingRules(server, egressTable)
}
