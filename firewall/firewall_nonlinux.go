//go:build !linux
// +build !linux

package firewall

import (
	"github.com/gravitl/netmaker/models"
)

type unimplementedFirewall struct{}

func (unimplementedFirewall) CreateChains() error {
	return nil
}
func (unimplementedFirewall) ForwardRule() error {
	return nil
}
func (unimplementedFirewall) InsertIngressRoutingRules(server string, r models.ExtClientInfo, egressRanges []string) error {
	return nil
}
func (unimplementedFirewall) AddIngressRoutingRule(server, extPeerKey, extPeerAddr string, peerInfo models.PeerRouteInfo) error {
	return nil
}
func (unimplementedFirewall) RefreshEgressRangesOnIngressGw(server string, ingressUpdate models.IngressInfo) error {
	return nil
}

func (unimplementedFirewall) RemoveRoutingRules(server, tableName, peerKey string) error {
	return nil
}

func (unimplementedFirewall) DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error {
	return nil
}
func (unimplementedFirewall) CleanRoutingRules(server, tableName string) {

}
func (unimplementedFirewall) FetchRuleTable(server string, ruleTableName string) ruletable {
	return ruletable{}
}

func (unimplementedFirewall) SaveRules(server, ruleTableName string, ruleTable ruletable) {

}
func (unimplementedFirewall) FlushAll() {

}

func (unimplementedFirewall) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	return nil
}
func (unimplementedFirewall) AddEgressRoutingRule(server string, egressInfo models.EgressInfo, peerInfo models.PeerRouteInfo) error {
	return nil
}

func (unimplementedFirewall) DeleteRuleTable(server, ruleTableName string) {

}

// newFirewall returns an unimplemented Firewall manager
func newFirewall() (firewallController, error) {
	return unimplementedFirewall{}, nil
}
