package router

import (
	"net"

	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerInfo struct {
	peerKey  wgtypes.Key
	peerAddr net.IPNet
	Allow    bool
}

func SetIngressRoutes(server string, ingressUpdate models.IngressInfo) error {

	ruleTable := fwCrtl.FetchRules(server, true)
	for extIndexKey, peerRuleMap := range ruleTable {
		// check if ext client route exists already for peer

		if _, ok := ingressUpdate.ExtPeers[extIndexKey]; !ok {
			// ext peer is deleted, flush out all rules
			fwCrtl.RemoveRoutingRules(server, extIndexKey)
			continue
		}
		extPeers := ingressUpdate.ExtPeers[extIndexKey]
		for peerKey := range peerRuleMap {
			if _, ok := extPeers.Peers[peerKey]; !ok {
				// peer is deleted for ext client, remove routing rule
				fwCrtl.DeleteRoutingRule(server, extIndexKey, peerKey)
			}
		}
	}

	for _, extInfo := range ingressUpdate.ExtPeers {
		fwCrtl.InsertIngressRoutingRules(server, extInfo)
	}

	return nil
}
