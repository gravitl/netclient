//go:build !linux
// +build !linux

package router

import (
	"github.com/gravitl/netmaker/models"
)

type unimplementedFirewall struct{}

func (unimplementedFirewall) CreateChains() error {
	return nil
}
func (unimplementedFirewall) InsertIngressRoutingRules(server string, r models.ExtClientInfo) error {
	return nil
}
func (unimplementedFirewall) AddIngressRoutingRule(server, extPeerKey string, peerInfo models.PeerExtInfo) error {
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

// newFirewall returns an unimplemented Firewall manager
func newFirewall() firewallController {
	return unimplementedFirewall{}
}
