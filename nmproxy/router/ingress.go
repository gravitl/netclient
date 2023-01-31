package router

import (
	"github.com/gravitl/netmaker/models"
)

func SetIngressRoutes(server string, ingressUpdate models.IngressInfo) error {

	ruleTable := fwCrtl.FetchRuleTable(server, ingressTable)
	for extIndexKey, ruleCfg := range ruleTable {
		// check if ext client route exists already for peer

		if _, ok := ingressUpdate.ExtPeers[extIndexKey]; !ok {
			// ext peer is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, ingressTable, extIndexKey)
			continue
		}
		extPeers := ingressUpdate.ExtPeers[extIndexKey]
		for peerKey := range ruleCfg.rulesMap {
			if _, ok := extPeers.Peers[peerKey]; !ok {
				// peer is deleted for ext client, remove routing rule
				fwCrtl.DeleteRoutingRule(server, ingressTable, extIndexKey, peerKey)
			}
		}
	}

	for _, extInfo := range ingressUpdate.ExtPeers {
		if _, ok := ruleTable[extInfo.ExtPeerKey.String()]; !ok {
			fwCrtl.InsertIngressRoutingRules(server, extInfo)
		} else {
			peerRules := ruleTable[extInfo.ExtPeerKey.String()]
			for _, peer := range extInfo.Peers {
				if _, ok := peerRules.rulesMap[peer.PeerKey.String()]; !ok {
					fwCrtl.AddIngRoutingRule(server, extInfo.ExtPeerKey.String(), peer)
				}
			}

		}

	}

	return nil
}
