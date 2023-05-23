package router

import (
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// SetEgressRoutes - sets the egress route for the gateway
func SetEgressRoutes(server string, egressUpdate map[string]models.EgressInfo) error {
	logger.Log(0, "----> setting egress routes")
	ruleTable := fwCrtl.FetchRuleTable(server, egressTable)
	for egressNodeID, ruleCfg := range ruleTable {

		if _, ok := egressUpdate[egressNodeID]; !ok {
			// egress GW is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, egressTable, egressNodeID)
			continue
		}
		egressInfo := egressUpdate[egressNodeID]
		for peerKey := range ruleCfg.rulesMap {
			if _, ok := egressInfo.GwPeers[peerKey]; !ok && peerKey != egressNodeID {
				// peer is deleted for ext client, remove routing rule
				fwCrtl.DeleteRoutingRule(server, egressTable, egressNodeID, peerKey)
			}
		}
	}

	for egressNodeID, egressInfo := range egressUpdate {
		if _, ok := ruleTable[egressNodeID]; !ok {
			// set up rules for the GW on first time creation
			fwCrtl.InsertEgressRoutingRules(server, egressInfo)
		} else {
			peerRules := ruleTable[egressNodeID]
			for _, peer := range egressInfo.GwPeers {
				if _, ok := peerRules.rulesMap[peer.PeerKey]; !ok {
					// add egress rules for the peer
					fwCrtl.AddEgressRoutingRule(server, egressInfo, peer)

				}
			}
		}
	}
	return nil
}

// DeleteEgressGwRoutes - deletes egress routes for the gateway
func DeleteEgressGwRoutes(server string) {
	fwCrtl.CleanRoutingRules(server, egressTable)
}
