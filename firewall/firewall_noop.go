//go:build darwin || freebsd
// +build darwin freebsd

package firewall

import (
	"github.com/gravitl/netmaker/models"
)

// noopFirewall is the shared no-op controller for platforms without a full
// firewall stack. Darwin embeds it and overrides inbound ACL defaults via pf.
type noopFirewall struct{}

func (noopFirewall) CreateChains() error { return nil }
func (noopFirewall) ForwardRule() error  { return nil }
func (noopFirewall) InsertIngressRoutingRules(server string, in models.IngressInfo) error {
	return nil
}
func (noopFirewall) AddIngressRoutingRule(server, extPeerKey, extPeerAddr string, peerInfo models.PeerRouteInfo) error {
	return nil
}
func (noopFirewall) RefreshEgressRangesOnIngressGw(server string, ingressUpdate models.IngressInfo) error {
	return nil
}
func (noopFirewall) ChangeACLInTarget(target string)  {}
func (noopFirewall) ChangeACLFwdTarget(target string) {}
func (noopFirewall) RemoveRoutingRules(server, tableName, peerKey string) error {
	return nil
}
func (noopFirewall) DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error {
	return nil
}
func (noopFirewall) CleanRoutingRules(server, tableName string) {}
func (noopFirewall) FetchRuleTable(server string, ruleTableName string) ruletable {
	return ruletable{}
}
func (noopFirewall) SaveRules(server, ruleTableName string, ruleTable ruletable) {}
func (noopFirewall) FlushAll()                                                   {}
func (noopFirewall) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	return nil
}
func (noopFirewall) DeleteRuleTable(server, ruleTableName string) {}
func (noopFirewall) AddAclRules(server string, aclRules map[string]models.AclRule) {
}
func (noopFirewall) UpsertAclRule(server string, aclRule models.AclRule) {}
func (noopFirewall) DeleteAclRule(server string, aclID string)           {}
func (noopFirewall) RestrictUserToUserComms(server string, ingressInfo models.IngressInfo) error {
	return nil
}
func (noopFirewall) AddAclEgressRules(server string, egressInfo models.EgressInfo) {
}
func (noopFirewall) DeleteAclEgressRule(server, nodeID, aclID string)                  {}
func (noopFirewall) UpsertAclEgressRule(server, nodeID string, aclRule models.AclRule) {}
func (noopFirewall) DeleteAllAclEgressRules(server, egressID string)                   {}
func (noopFirewall) AddDropRules([]ruleInfo)                                           {}
