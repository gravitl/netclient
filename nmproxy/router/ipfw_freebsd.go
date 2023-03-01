package router

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

type ipfwManager struct {
	ingRules     serverrulestable
	engressRules serverrulestable
	mux          sync.Mutex
}

// ipfwManager.CreateChains - initializes IPFW
func (i *ipfwManager) CreateChains() error {
	commands := []string{`firewall_enable="YES"`, `firewall_type="OPEN"`, `ipfw_enable="YES"`}
	for _, cmd := range commands {
		if err := exec.Command("sysrc", cmd).Run(); err != nil {
			return err
		}
	}
	return nil
}

// ipfwManager.InsertIngressRoutingRules - not implemented
func (i *ipfwManager) InsertIngressRoutingRules(server string, r models.ExtClientInfo, egressRanges []string) error {
	return nil
}

// ipfwManager.AddIngressRoutingRule - not implemented
func (i *ipfwManager) AddIngressRoutingRule(server, extPeerKey, extPeerAddr string, peerInfo models.PeerRouteInfo) error {
	return nil
}

// ipfwManager.RefreshEgressRangesOnIngressGw - not implemented
func (i *ipfwManager) RefreshEgressRangesOnIngressGw(server string, ingressUpdate models.IngressInfo) error {
	return nil
}

// ipfwManager.RemoveRoutingRules - remove routing rules related to a peer
func (i *ipfwManager) RemoveRoutingRules(server, ruletableName, peerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[peerKey]; !ok {
		return errors.New("peer not found in rule table: " + peerKey)
	}
	for _, rules := range rulesTable[peerKey].rulesMap {
		for _, rule := range rules {
			if err := i.deleteRule(rule.rule[1]); err != nil {
				logger.Log(0, fmt.Sprintf("ipfw: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err))
			}
		}
	}
	delete(rulesTable, peerKey)
	return nil
}

// ipfwManager.DeleteRoutingRule - removes a rule pair given source and destination peer keys
func (i *ipfwManager) DeleteRoutingRule(server, ruletableName, srcPeerKey, dstPeerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[srcPeerKey]; !ok {
		return errors.New("peer not found in rule table: " + srcPeerKey)
	}
	if rules, ok := rulesTable[srcPeerKey].rulesMap[dstPeerKey]; ok {
		for _, rule := range rules {
			if err := i.deleteRule(rule.rule[1]); err != nil {
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, srcPeerKey, err)
			}
		}
		delete(rulesTable[srcPeerKey].rulesMap, dstPeerKey)
	} else {
		return errors.New("rules not found for: " + dstPeerKey)
	}
	return nil
}

// ipfwManager.CleanRoutingRules - clean routing rules
func (i *ipfwManager) CleanRoutingRules(server, ruleTableName string) {
	ruleTable := i.FetchRuleTable(server, ruleTableName)
	defer i.DeleteRuleTable(server, ruleTableName)
	i.mux.Lock()
	defer i.mux.Unlock()
	for _, rulesCfg := range ruleTable {
		for key, rules := range rulesCfg.rulesMap {
			for _, rule := range rules {
				// rule.rule[1] contains the number for the rule which is used for deletion
				// 2nd position in the rulespec array will always contain the rule number
				if err := i.deleteRule(rule.rule[1]); err != nil {
					logger.Log(0, fmt.Sprintf("failed to delete rule [%s]: %+v, Err: %s", key, rule, err.Error()))
				}
			}
		}
	}
}

// ipfwManager.FetchRuleTable - fetch ingress/egress ruletable
func (i *ipfwManager) FetchRuleTable(server string, tableName string) ruletable {
	i.mux.Lock()
	defer i.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = i.ingRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	case egressTable:
		rules = i.engressRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	}
	return rules
}

// ipfwManager.SaveRules - save rules to the ruletable
func (i *ipfwManager) SaveRules(server, tableName string, rules ruletable) {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(1, "Saving rules to table: ", tableName)
	switch tableName {
	case ingressTable:
		i.ingRules[server] = rules
	case egressTable:
		i.engressRules[server] = rules
	}
}

// ipfwManager.FlushAll - delete all rules
func (i *ipfwManager) FlushAll() {
	if err := execFw("-f", "flush"); err != nil {
		logger.Log(0, "error flushing ipfw rules:", err.Error())
	}
}

// ipfwManager.InsertEgressRoutingRules - inserts egress routes for the GW peers
func (i *ipfwManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	ruleTable[egressInfo.EgressID] = rulesCfg{
		isIpv4:   isAddrIpv4(egressInfo.EgressGwAddr.String()),
		rulesMap: make(map[string][]ruleInfo),
	}
	egressGwRoutes := []ruleInfo{}
	for _, peer := range egressInfo.GwPeers {
		if !peer.Allow {
			continue
		}
		ruleSpec := []string{"add", getRuleNumber(), "allow", "all", "from", peer.PeerAddr.String(),
			"to", strings.Join(egressInfo.EgressGWCfg.Ranges, ","), "via", ncutils.GetInterfaceName()}
		if err := execFw(ruleSpec...); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ruleTable[egressInfo.EgressID].rulesMap[peer.PeerKey] = []ruleInfo{{rule: ruleSpec}}
			egressGwRoutes = append(egressGwRoutes, ruleInfo{rule: ruleSpec})
		}
	}
	ruleTable[egressInfo.EgressID].rulesMap[egressInfo.EgressID] = egressGwRoutes
	return nil
}

// ipfwManager.AddEgressRoutingRule - inserts egress routes for the GW peers
func (i *ipfwManager) AddEgressRoutingRule(server string, egressInfo models.EgressInfo, peer models.PeerRouteInfo) error {
	if !peer.Allow {
		return nil
	}
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	ruleSpec := []string{"add", getRuleNumber(), "allow", "all", "from", peer.PeerAddr.String(),
		"to", strings.Join(egressInfo.EgressGWCfg.Ranges, ","), "via", ncutils.GetInterfaceName()}
	if err := execFw(ruleSpec...); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	} else {
		ruleTable[egressInfo.EgressID].rulesMap[peer.PeerKey] = []ruleInfo{{rule: ruleSpec}}
	}
	return nil
}

// ipfwManager.DeleteRuleTable - delete a rule from ruletable
func (i *ipfwManager) DeleteRuleTable(server, ruleTableName string) {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(1, "Deleting rules table: ", server, ruleTableName)
	switch ruleTableName {
	case ingressTable:
		delete(i.ingRules, server)
	case egressTable:
		delete(i.engressRules, server)
	}
}

var ruleCounter uint64 = 1

// generates a number for ipfw rules (auto-incremented)
func getRuleNumber() string {
	ruleCounter++
	return fmt.Sprintf("%d", ruleCounter)
}

func (i *ipfwManager) deleteRule(number string) error {
	return execFw("delete", number)
}

func execFw(args ...string) error {
	stdout, err := exec.Command("ipfw", args...).Output()
	fmt.Println(string(stdout))
	return err
}
