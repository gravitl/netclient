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
func (unimplementedFirewall) InsertIngressRoutingRules(server string, in models.IngressInfo) error {
	return nil
}
func (unimplementedFirewall) AddIngressRoutingRule(server, extPeerKey, extPeerAddr string, peerInfo models.PeerRouteInfo) error {
	return nil
}
func (unimplementedFirewall) RefreshEgressRangesOnIngressGw(server string, ingressUpdate models.IngressInfo) error {
	return nil
}
func (unimplementedFirewall) ChangeACLInTarget(target string)  {}
func (unimplementedFirewall) ChangeACLFwdTarget(target string) {}
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

func (unimplementedFirewall) DeleteRuleTable(server, ruleTableName string) {

}

func (unimplementedFirewall) AddAclRules(server string, aclRules map[string]models.AclRule) {

}
func (unimplementedFirewall) UpsertAclRule(server string, aclRule models.AclRule) {

}

func (unimplementedFirewall) DeleteAclRule(server string, aclID string) {

}
func (unimplementedFirewall) RestrictUserToUserComms(server string, ingressInfo models.IngressInfo) error {
	return nil
}
func (unimplementedFirewall) AddAclEgressRules(server string, aclRules map[string]models.AclRule) {}
func (unimplementedFirewall) DeleteAclEgressRule(server, aclID string)                            {}
func (unimplementedFirewall) UpsertAclEgressRule(server string, aclRule models.AclRule)           {}
func (unimplementedFirewall) AddDropRules([]ruleInfo)                                             {}

// newFirewall returns an unimplemented Firewall manager
func newFirewall() (firewallController, error) {
	return unimplementedFirewall{}, nil
}
