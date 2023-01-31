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
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	ingRules   serverrulestable
	mux        sync.Mutex
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
func (i *iptablesManager) CleanRoutingRules(server string) {
	i.mux.Lock()
	defer i.mux.Unlock()

	// errMSGFormat := "iptables: failed cleaning %s chain %s,error: %v"

}

// CreateChains - creates default chains and rules
func (i *iptablesManager) CreateChains() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	cleanup(i.ipv4Client, defaultIpTable, netmakerFilterChain)
	cleanup(i.ipv4Client, defaultNatTable, netmakerNatChain)
	cleanup(i.ipv6Client, defaultIpTable, netmakerFilterChain)
	cleanup(i.ipv6Client, defaultNatTable, netmakerNatChain)

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
	}
	err = createChain(i.ipv6Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
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
		ruleSpec := []string{"-i", ncutils.GetInterfaceName(), "-j", "DROP"}
		err := i.Append(table, chain, ruleSpec...)
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

// InsertIngressRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *iptablesManager) InsertIngressRoutingRules(server string, extinfo models.ExtClientInfo) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	prefix, err := netip.ParsePrefix(extinfo.ExtPeerKey.String())
	if err != nil {
		return err
	}
	isIpv4 := true
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		isIpv4 = false
	}
	ruleTable := i.FetchRuleTable(server, ingressTable)
	ruleTable[extinfo.ExtPeerKey.String()] = rulesCfg{
		isIpv4:   isIpv4,
		rulesMap: make(map[string][]RuleInfo),
	}
	//iptables -A FORWARD -s 10.24.52.252/32 -j netmakerfilter
	//iptables -A newchain -d 10.24.52.3/32 -j ACCEPT
	ruleSpec := []string{"-s", extinfo.ExtPeerAddr.String(), "-j", netmakerFilterChain}
	err = iptablesClient.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	ruleTable[extinfo.ExtPeerKey.String()].rulesMap[extinfo.ExtPeerKey.String()] = []RuleInfo{

		{

			rule:  ruleSpec,
			chain: iptableFWDChain,
			table: defaultIpTable,
		},
	}

	for _, peerInfo := range extinfo.Peers {
		ruleSpec := []string{"-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
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
	ruleSpec = []string{"-s", extinfo.ExtPeerAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	err = iptablesClient.Append(defaultNatTable, netmakerNatChain, ruleSpec...)
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
	err = iptablesClient.Append(defaultNatTable, netmakerNatChain, ruleSpec...)
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
func cleanup(i *iptables.IPTables, table, chain string) {

	i.ClearAndDeleteChain(table, chain)
	i.ClearAll()
}

func (i *iptablesManager) FetchRuleTable(server string, tableName string) ruletable {
	i.mux.Lock()
	defer i.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = i.ingRules[server]
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
	i.mux.Lock()
	defer i.mux.Unlock()
	// err := iptablesClient.DeleteIfExists(table, chain, existingRule...)
	// if err != nil {
	// 	return fmt.Errorf("iptables: error while removing existing %s rule for %s: %v", getIptablesRuleType(table), pair.destination, err)
	// }
	// delete(i.rules[ipVersion], ruleKey)
	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) DeleteRoutingRule(server, ruletableName, srcPeerKey, dstPeerKey string) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	return nil
}

// removeRoutingRule removes an iptables rule
func (i *iptablesManager) removeIngRoutingRule(server, indexedPeerKey, peerKey string) error {
	var err error
	var rulesInfo []RuleInfo
	var ok bool
	ruleTable := i.FetchRuleTable(server, ingressTable)
	if _, ok = ruleTable[indexedPeerKey]; ok {
		if rulesInfo, ok = ruleTable[indexedPeerKey].rulesMap[peerKey]; !ok {
			return errors.New("no rules found: " + indexedPeerKey + ", " + peerKey)
		}
	} else {
		return errors.New("no rules found: " + indexedPeerKey)
	}
	for _, rInfo := range rulesInfo {
		iptablesClient := i.ipv4Client
		if !ruleTable[indexedPeerKey].isIpv4 {
			iptablesClient = i.ipv6Client
		}
		err = iptablesClient.DeleteIfExists(rInfo.table, rInfo.chain, rInfo.rule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %v rule from %s: %v", rInfo.rule, rInfo.chain, err)
		}
	}

	delete(i.ingRules[indexedPeerKey], peerKey)
	return nil
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}
