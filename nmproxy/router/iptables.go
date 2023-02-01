package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

// constants needed to manage and create iptable rules
const (
	ipv6                = "ipv6"
	ipv4                = "ipv4"
	defaultIpTable      = "filter"
	netmakerFilterChain = "netmakerfilter"
	defaultNatTable     = "nat"
	netmakerNatChain    = "netmakernat"
	iptableFWDChain     = "FORWARD"
	nattablePRTChain    = "POSTROUTING"
)

type RuleInfo struct {
	rule  []string
	table string
	chain string
}

type iptablesManager struct {
	ctx          context.Context
	stop         context.CancelFunc
	ipv4Client   *iptables.IPTables
	ipv6Client   *iptables.IPTables
	ingRules     serverrulestable
	defaultRules ruletable
	mux          sync.Mutex
}

func createChain(iptables *iptables.IPTables, table, newChain string) error {

	chains, err := iptables.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s %s table chains, error: %v", iptablesProtoToString(iptables.Proto()), table, err)
	}

	shouldCreateChain := true
	for _, chain := range chains {
		if chain == newChain {
			shouldCreateChain = false
		}
	}

	if shouldCreateChain {
		err = iptables.NewChain(table, newChain)
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", iptablesProtoToString(iptables.Proto()), newChain, table, err)
		}

		insertDefaultRules(iptables, table, newChain)

	}
	return nil
}

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (i *iptablesManager) CleanRoutingRules(server, ruleTableName string) {
	ruleTable := i.FetchRuleTable(server, ruleTableName)
	i.mux.Lock()
	defer i.mux.Unlock()
	for _, rulesCfg := range ruleTable {
		for _, rules := range rulesCfg.rulesMap {
			iptablesClient := i.ipv4Client
			if !rulesCfg.isIpv4 {
				iptablesClient = i.ipv6Client
			}
			for _, rule := range rules {
				iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			}
		}
	}

}

// CreateChains - creates default chains and rules
func (i *iptablesManager) CreateChains() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	i.cleanup(defaultIpTable, netmakerFilterChain)
	i.cleanup(defaultNatTable, netmakerNatChain)

	//errMSGFormat := "iptables: failed creating %s chain %s,error: %v"

	err := createChain(i.ipv4Client, defaultIpTable, netmakerFilterChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	// set default rules
	insertDefaultRules(i.ipv4Client, defaultIpTable, netmakerFilterChain)
	insertDefaultRules(i.ipv4Client, defaultNatTable, netmakerNatChain)

	err = createChain(i.ipv6Client, defaultIpTable, netmakerFilterChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv6Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	// set default rules
	insertDefaultRules(i.ipv6Client, defaultIpTable, netmakerFilterChain)
	insertDefaultRules(i.ipv6Client, defaultNatTable, netmakerNatChain)

	return nil
}

func insertDefaultRules(i *iptables.IPTables, table, chain string) {
	//iptables -A newchain -i netmaker -j DROP
	//iptables -A newchain -j RETURN
	if table == defaultIpTable {
		ruleSpec := []string{"-i", ncutils.GetInterfaceName(), "-j", netmakerFilterChain}
		err := i.Insert(table, iptableFWDChain, 1, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}

		ruleSpec = []string{"-i", ncutils.GetInterfaceName(), "-j", "DROP"}
		err = i.Append(table, chain, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
		ruleSpec = []string{"-j", "RETURN"}
		err = i.Append(table, chain, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
	} else {
		//	iptables -t nat -A POSTROUTING  -o netmaker -j netmakernat
		ruleSpec := []string{"-o", ncutils.GetInterfaceName(), "-j", chain}
		err := i.Append(table, nattablePRTChain, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
		// iptables -t nat -A netmakernat -j RETURN
		ruleSpec = []string{"-j", "RETURN"}
		err = i.Append(table, chain, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
	}

}

func (i *iptablesManager) AddIngRoutingRule(server, extPeerKey string, peerInfo models.PeerExtInfo) error {
	ruleTable := i.FetchRuleTable(server, ingressTable)
	defer i.SaveRules(server, ingressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	prefix, err := netip.ParsePrefix(peerInfo.PeerAddr.String())
	if err != nil {
		return err
	}
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
	}

	ruleSpec := []string{"-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
	err = iptablesClient.Insert(defaultIpTable, netmakerFilterChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	ruleTable[extPeerKey].rulesMap[peerInfo.PeerKey.String()] = []RuleInfo{
		{
			rule:  ruleSpec,
			chain: netmakerFilterChain,
			table: defaultIpTable,
		},
	}
	return nil
}

func (i *iptablesManager) InsertRoutingRule(server, extPeerKey string, peerInfo models.PeerExtInfo) error {
	ruleTable := i.FetchRuleTable(server, ingressTable)
	defer i.SaveRules(server, ingressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	prefix, err := netip.ParsePrefix(peerInfo.PeerAddr.String())
	if err != nil {
		return err
	}
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
	}

	ruleSpec := []string{"-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
	err = iptablesClient.Insert(defaultIpTable, netmakerFilterChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	ruleTable[extPeerKey].rulesMap[peerInfo.PeerKey.String()] = []RuleInfo{
		{
			rule:  ruleSpec,
			chain: netmakerFilterChain,
			table: defaultIpTable,
		},
	}
	return nil
}

// InsertIngressRoutingRules inserts an iptables rule pair to the netmaker chain and if enabled, to the nat chain
func (i *iptablesManager) InsertIngressRoutingRules(server string, extinfo models.ExtClientInfo) error {
	ruleTable := i.FetchRuleTable(server, ingressTable)
	defer i.SaveRules(server, ingressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(0, "Inserting Rules")
	prefix, err := netip.ParsePrefix(extinfo.ExtPeerAddr.String())
	if err != nil {
		return err
	}
	logger.Log(0, "------------> HEREEEEE2")
	isIpv4 := true
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		isIpv4 = false
	}

	ruleTable[extinfo.ExtPeerKey.String()] = rulesCfg{
		isIpv4:   isIpv4,
		rulesMap: make(map[string][]RuleInfo),
	}
	logger.Log(0, "------------> HEREEEEE1")

	for _, peerInfo := range extinfo.Peers {
		if !peerInfo.Allow {
			continue
		}
		ruleSpec := []string{"-s", extinfo.ExtPeerAddr.String(), "-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
		logger.Log(0, fmt.Sprintf("-----> adding rule: %+v", ruleSpec))
		err := iptablesClient.Insert(defaultIpTable, netmakerFilterChain, 1, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
		ruleTable[extinfo.ExtPeerKey.String()].rulesMap[peerInfo.PeerKey.String()] = []RuleInfo{
			{

				rule:  ruleSpec,
				chain: netmakerFilterChain,
				table: defaultIpTable,
			},
		}

	}
	if !extinfo.Masquerade {
		return nil
	}
	// iptables -t nat -A netmakernat  -s 10.24.52.252/32 -o netmaker -j MASQUERADE
	// iptables -t nat -A netmakernat -d 10.24.52.252/32 -o netmaker -j MASQUERADE
	ruleSpec := []string{"-s", extinfo.ExtPeerAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	logger.Log(0, fmt.Sprintf("----->[NAT] adding rule: %+v", ruleSpec))
	err = iptablesClient.Insert(defaultNatTable, netmakerNatChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	routes := ruleTable[extinfo.ExtPeerKey.String()].rulesMap[extinfo.ExtPeerKey.String()]
	routes = append(routes, RuleInfo{
		rule:  ruleSpec,
		table: defaultNatTable,
		chain: netmakerNatChain,
	})
	ruleSpec = []string{"-d", extinfo.ExtPeerAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	logger.Log(0, fmt.Sprintf("----->[NAT] adding rule: %+v", ruleSpec))
	err = iptablesClient.Insert(defaultNatTable, netmakerNatChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	routes = append(routes, RuleInfo{
		rule:  ruleSpec,
		table: defaultNatTable,
		chain: netmakerNatChain,
	})
	ruleTable[extinfo.ExtPeerKey.String()].rulesMap[extinfo.ExtPeerKey.String()] = routes

	return nil
}

func (i *iptablesManager) cleanup(table, chain string) {
	// remove jump rules

	i.ipv4Client.ClearAndDeleteChain(table, chain)
	i.ipv6Client.ClearAndDeleteChain(table, chain)
}

func (i *iptablesManager) FetchRuleTable(server string, tableName string) ruletable {
	i.mux.Lock()
	defer i.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = i.ingRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	}
	return rules
}

func (i *iptablesManager) SaveRules(server, tableName string, rules ruletable) {
	i.mux.Lock()
	defer i.mux.Unlock()
	switch tableName {
	case ingressTable:
		i.ingRules[server] = rules
	}
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) RemoveRoutingRules(server, ruletableName, peerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[peerKey]; !ok {
		return errors.New("peer not found in rule table: " + peerKey)
	}
	iptablesClient := i.ipv4Client
	if !rulesTable[peerKey].isIpv4 {
		iptablesClient = i.ipv6Client
	}

	for _, rules := range rulesTable[peerKey].rulesMap {
		for _, rule := range rules {
			err := iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err)
			}
		}

	}
	delete(rulesTable, peerKey)
	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) DeleteRoutingRule(server, ruletableName, srcPeerKey, dstPeerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[srcPeerKey]; !ok {
		return errors.New("peer not found in rule table: " + srcPeerKey)
	}
	iptablesClient := i.ipv4Client
	if !rulesTable[srcPeerKey].isIpv4 {
		iptablesClient = i.ipv6Client
	}
	if rules, ok := rulesTable[srcPeerKey].rulesMap[dstPeerKey]; ok {
		for _, rule := range rules {
			err := iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, srcPeerKey, err)
			}
		}
	} else {
		return errors.New("rules not found for: " + dstPeerKey)
	}

	return nil
}

func (i *iptablesManager) FlushAll() {
	i.mux.Lock()
	defer i.mux.Unlock()
	i.cleanup(defaultIpTable, netmakerFilterChain)
	i.cleanup(defaultNatTable, netmakerNatChain)
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}
