package router

import (
	"github.com/gravitl/netmaker/models"
)

type ipfwManager struct{}

func (i *ipfwManager) CreateChains() error {
	return nil
}

func (i *ipfwManager) InsertIngressRoutingRules(server string, r models.ExtClientInfo, egressRanges []string) error {
	return nil
}

func (i *ipfwManager) AddIngressRoutingRule(server, extPeerKey, extPeerAddr string, peerInfo models.PeerRouteInfo) error {
	return nil
}

func (i *ipfwManager) RefreshEgressRangesOnIngressGw(server string, ingressUpdate models.IngressInfo) error {
	return nil
}

func (i *ipfwManager) RemoveRoutingRules(server, tableName, peerKey string) error {
	return nil
}

func (i *ipfwManager) DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error {
	return nil
}

func (i *ipfwManager) CleanRoutingRules(server, tableName string) {
}

func (i *ipfwManager) FetchRuleTable(server string, ruleTableName string) ruletable {
	return ruletable{}
}

func (i *ipfwManager) SaveRules(server, ruleTableName string, ruleTable ruletable) {
}

func (i *ipfwManager) FlushAll() {
}

func (i *ipfwManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	return nil
}

func (i *ipfwManager) AddEgressRoutingRule(server string, egressInfo models.EgressInfo, peerInfo models.PeerRouteInfo) error {
	return nil
}

func (i *ipfwManager) DeleteRuleTable(server, ruleTableName string) {
}
