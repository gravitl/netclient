package router

import (
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// SetIngressRoutes - feed ingress update to firewall controller to add/remove routing rules
func SetIngressRoutes(server string, ingressUpdate models.IngressInfo) error {
	logger.Log(0, "----> setting ingress routes")
	ruleTable := fwCrtl.FetchRuleTable(server, ingressTable)
	for extPeerKey, ruleCfg := range ruleTable {

		if _, ok := ingressUpdate.ExtPeers[extPeerKey]; !ok {
			// ext peer is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, ingressTable, extPeerKey)
			continue
		}
		extPeers := ingressUpdate.ExtPeers[extPeerKey]
		for peerKey := range ruleCfg.rulesMap {
			if _, ok := extPeers.Peers[peerKey]; !ok && peerKey != extPeerKey {
				// peer is deleted for ext client, remove routing rule
				fwCrtl.DeleteRoutingRule(server, ingressTable, extPeerKey, peerKey)
			}
		}
	}

	for _, extInfo := range ingressUpdate.ExtPeers {
		if _, ok := ruleTable[extInfo.ExtPeerKey]; !ok {
			err := fwCrtl.InsertIngressRoutingRules(server, extInfo)
			if err != nil {
				logger.Log(0, "falied to set ingress routes: ", err.Error())
			}
		} else {
			peerRules := ruleTable[extInfo.ExtPeerKey]
			for _, peer := range extInfo.Peers {
				if _, ok := peerRules.rulesMap[peer.PeerKey]; !ok {
					fwCrtl.AddIngressRoutingRule(server, extInfo.ExtPeerKey, peer)
				}
			}
		}
	}
	return nil
}

// DeleteIngressRules - removes the rules of ingressGW
func DeleteIngressRules(server string) {
	fwCrtl.CleanRoutingRules(server, ingressTable)
}
