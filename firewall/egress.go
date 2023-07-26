package firewall

import (
	"errors"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// SetEgressRoutes - sets the egress route for the gateway
func SetEgressRoutes(server string, egressUpdate map[string]models.EgressInfo) error {
	if fwCrtl == nil {
		return errors.New("firewall is not initialized yet")
	}
	logger.Log(0, "----> setting egress routes")
	ruleTable := fwCrtl.FetchRuleTable(server, egressTable)
	for egressNodeID := range ruleTable {
		if _, ok := egressUpdate[egressNodeID]; !ok {
			// egress GW is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
			continue
		}

	}

	for egressNodeID, egressInfo := range egressUpdate {
		if _, ok := ruleTable[egressNodeID]; !ok {
			// set up rules for the GW on first time creation
			fwCrtl.InsertEgressRoutingRules(server, egressInfo)
			egressMapMutex.Lock()
			currEgressRangesMap[egressNodeID] = egressInfo.EgressGWCfg.Ranges
			egressMapMutex.Unlock()
			continue
		}
		egressMapMutex.RLock()
		currEgressRanges := currEgressRangesMap[egressNodeID]
		egressMapMutex.RUnlock()
		if len(currEgressRanges) != len(egressInfo.EgressGWCfg.Ranges) {
			// refresh egress routes for any modification in the ranges
			slog.Info("refreshing egress routes", "nodeID", egressNodeID)
			fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
			fwCrtl.InsertEgressRoutingRules(server, egressInfo)
			egressMapMutex.Lock()
			currEgressRangesMap[egressNodeID] = egressInfo.EgressGWCfg.Ranges
			egressMapMutex.Unlock()
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
