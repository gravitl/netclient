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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	ipVersion string
	rule      []string
	table     string
	chain     string
}

type iptablesManager struct {
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	ingRules   map[string]map[string][]RuleInfo
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
func (i *iptablesManager) CleanRoutingRules() {
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

// InsertIngressRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *iptablesManager) InsertIngressRoutingRules(r ingressRoute) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	prefix, err := netip.ParsePrefix(r.remoteClientAddr.String())
	if err != nil {
		return err
	}
	ipVersion := ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = ipv6
	}
	i.ingRules[r.remotePeerKey.String()] = make(map[string][]RuleInfo)
	//iptables -A FORWARD -s 10.24.52.252/32 ! -d 10.24.52.4/32 -p icmp -j newchain
	//iptables -A newchain -d 10.24.52.3/32 -p icmp -j ACCEPT
	ruleSpec := []string{"-s", r.remoteClientAddr.String(), "-j", netmakerFilterChain}
	err = iptablesClient.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()] = []RuleInfo{

		{
			ipVersion: ipVersion,
			rule:      ruleSpec,
			chain:     iptableFWDChain,
			table:     defaultIpTable,
		},
	}

	for _, peerInfo := range r.peers {
		ruleSpec := []string{"-d", peerInfo.peerAddr.String(), "-j", "ACCEPT"}
		err := iptablesClient.Insert(defaultIpTable, netmakerFilterChain, 1, ruleSpec...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		}
		i.ingRules[r.remotePeerKey.String()][peerInfo.peerKey.String()] = []RuleInfo{
			{
				ipVersion: ipVersion,
				rule:      ruleSpec,
				chain:     netmakerFilterChain,
				table:     defaultIpTable,
			},
		}

	}
	if !r.masquerade {
		return nil
	}
	// iptables -t nat -A netmakernat  -s 10.24.52.252/32 -o netmaker -j MASQUERADE
	// iptables -t nat -A netmakernat -d 10.24.52.252/32 -o netmaker -j MASQUERADE
	ruleSpec = []string{"-s", r.remoteClientAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	err = iptablesClient.Append(defaultNatTable, netmakerNatChain, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	routes := i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()]
	routes = append(routes, RuleInfo{
		ipVersion: ipVersion,
		rule:      ruleSpec,
		table:     defaultNatTable,
		chain:     netmakerNatChain,
	})
	ruleSpec = []string{"-d", r.remoteClientAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	err = iptablesClient.Append(defaultNatTable, netmakerNatChain, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	routes = append(routes, RuleInfo{
		ipVersion: ipVersion,
		rule:      ruleSpec,
		table:     defaultNatTable,
		chain:     netmakerNatChain,
	})
	i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()] = routes

	return nil
}
func cleanup(i *iptables.IPTables, table, chain string) {

	i.ClearAndDeleteChain(table, chain)
	i.ClearAll()
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) RemoveRoutingRules(peerKey wgtypes.Key) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	return nil
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) DeleteRoutingRule(srcPeerKey, dstPeerKey wgtypes.Key) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	return nil
}

// removeRoutingRule removes an iptables rule
func (i *iptablesManager) removeIngRoutingRule(indexedPeerKey, peerKey wgtypes.Key) error {
	var err error
	var rulesInfo []RuleInfo
	var ok bool
	if rulesInfo, ok = i.ingRules[indexedPeerKey.String()][peerKey.String()]; !ok {
		return errors.New("no rules found")
	}
	for _, rInfo := range rulesInfo {
		iptablesClient := i.ipv4Client
		if rInfo.ipVersion == ipv6 {
			iptablesClient = i.ipv6Client
		}
		err = iptablesClient.DeleteIfExists(rInfo.table, rInfo.chain, rInfo.rule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %v rule from %s: %v", rInfo.rule, rInfo.chain, err)
		}
	}

	delete(i.ingRules[indexedPeerKey.String()], peerKey.String())
	return nil
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}
