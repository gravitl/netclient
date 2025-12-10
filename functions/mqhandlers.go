package functions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/firewall"
	"github.com/gravitl/netclient/flow"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MQTimeout - time out for mqtt connections
const MQTimeout = 30

// All -- mqtt message hander for all ('#') topics
var All mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	slog.Info("default message handler -- received message but not handling", "topic", msg.Topic())
}

var mNMutex = sync.Mutex{}  // used to mutex functions of the interface
var upgMutex = sync.Mutex{} // used to mutex functions of upgrade

// NodeUpdate -- mqtt message handler for /update/<NodeID> topic
func NodeUpdate(client mqtt.Client, msg mqtt.Message) {
	if len(msg.Payload()) == 0 {
		return
	}
	network := parseNetworkFromTopic(msg.Topic())
	slog.Info("processing node update for network", "network", network)
	node := config.GetNode(network)
	server := config.GetServer(node.Server)
	if server == nil {
		return
	}
	data, err := decryptAESGCM(config.Netclient().TrafficKeyPublic[0:32], msg.Payload())
	if err != nil {
		slog.Warn("error decrypting message", "warn", err)
		data, err = decryptMsg(server.Name, msg.Payload())
		if err != nil {
			slog.Error("error decrypting message", "error", err)
			return
		}
	} else {
		data, err = unzipPayload(data)
		if err != nil {
			slog.Error("error unzipping message", "error", err)
			return
		}
	}

	serverNode := models.Node{}
	if err = json.Unmarshal([]byte(data), &serverNode); err != nil {
		slog.Error("error unmarshalling node update data", "error", err)
		return
	}
	newNode := config.Node{}
	newNode.CommonNode = serverNode.CommonNode

	// see if cache hit, if so skip
	var currentMessage = read(newNode.Network, lastNodeUpdate)
	if currentMessage == string(data) {
		slog.Info("cache hit on node update ... skipping")
		return
	}
	insert(newNode.Network, lastNodeUpdate, string(data)) // store new message in cache
	slog.Info("received node update", "node", newNode.ID, "network", newNode.Network)
	// check if interface needs to delta
	ifaceDelta := wireguard.IfaceDelta(&node, &newNode)
	//nodeCfg.Node = newNode
	switch newNode.Action {
	case models.NODE_DELETE:
		slog.Info("received delete request for", "node", newNode.ID, "network", newNode.Network)
		unsubscribeNode(client, &newNode)
		if _, err = LeaveNetwork(newNode.Network, true); err != nil {
			if !strings.Contains("rpc error", err.Error()) {
				slog.Error("failed to leave network, please check that local files for network were removed", "network", newNode.Network, "error", err)
				return
			}
		}
		slog.Info("node was deleted", "node", newNode.ID, "network", newNode.Network)
		return
	case models.NODE_FORCE_UPDATE:
		ifaceDelta = true
	case models.NODE_NOOP:
	default:
	}
	if ifaceDelta { // if a change caused an ifacedelta we need to notify the server to update the peers
		// Save new config
		newNode.Action = models.NODE_NOOP
		config.UpdateNodeMap(network, newNode)
		if err := config.WriteNodeConfig(); err != nil {
			slog.Warn("failed to write node config", "error", err)
		}
		nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
		if err := nc.Configure(); err != nil {
			slog.Error("could not configure netmaker interface", "error", err)
			return
		}
		wireguard.SetRoutesFromCache()
		time.Sleep(time.Second)
		if server.ManageDNS {
			dns.GetDNSServerInstance().Stop()
			dns.GetDNSServerInstance().Start()
		}

		doneErr := publishSignal(&newNode, DONE)
		if doneErr != nil {
			slog.Warn("could not notify server to update peers after interface change", "network:", newNode.Network, "error", doneErr)
		} else {
			slog.Info("signalled finished interface update to server", "network", newNode.Network)
		}
	}
}

// DNSSync -- mqtt message handler for host/dns/sync/<network id> topic
func DNSSync(client mqtt.Client, msg mqtt.Message) {
	if len(msg.Payload()) == 0 {
		return
	}
	network := parseServerFromTopic(msg.Topic())

	var dnsEntries []models.DNSEntry
	err := json.Unmarshal([]byte(msg.Payload()), &dnsEntries)
	if err != nil {
		slog.Error("error unmarshalling DNS data", "error", err)
		return
	}

	if len(dnsEntries) > 0 {
		err = dns.SyncDNS(network, dnsEntries)
		if err != nil {
			slog.Error("synchronize DNS error ", "error", err.Error())
		}
	}
}

// HostPeerUpdate - mq handler for host peer update peers/host/<HOSTID>/<SERVERNAME>
func HostPeerUpdate(client mqtt.Client, msg mqtt.Message) {
	var peerUpdate models.HostPeerUpdate
	var err error
	if len(msg.Payload()) == 0 {
		return
	}
	if len(config.GetNodes()) == 0 {
		slog.Info("skipping unwanted peer update, no nodes exist")
		return
	}
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	slog.Info("processing peer update for server", "server", serverName)
	data, err := decryptAESGCM(config.Netclient().TrafficKeyPublic[0:32], msg.Payload())
	if err != nil {
		slog.Warn("error decrypting message", "warn", err)
		data, err = decryptMsg(server.Name, msg.Payload())
		if err != nil {
			slog.Error("error decrypting message", "error", err)
			return
		}
	} else {
		data, err = unzipPayload(data)
		if err != nil {
			slog.Error("error unzipping message", "error", err)
			return
		}
	}

	err = json.Unmarshal([]byte(data), &peerUpdate)
	if err != nil {
		slog.Error("error unmarshalling peer data", "error", err)
		return
	}
	if peerUpdate.ServerConfig.PeerConnectionCheckInterval != "" &&
		peerUpdate.ServerConfig.PeerConnectionCheckInterval != server.PeerConnectionCheckInterval {
		sec, err := strconv.Atoi(peerUpdate.ServerConfig.PeerConnectionCheckInterval)
		if err == nil && sec > 0 {
			networking.PeerConnectionCheckInterval = time.Duration(sec) * time.Second
		}
	}
	if server.IsPro {
		if autoRelayConnTicker != nil {
			autoRelayConnTicker.Reset(networking.PeerConnectionCheckInterval)
		}
		if networking.PeerLocalEndpointConnTicker != nil {
			networking.PeerLocalEndpointConnTicker.Reset(networking.PeerConnectionCheckInterval)
		}
		if wireguard.HaEgressTicker != nil {
			wireguard.HaEgressTicker.Reset(wireguard.HaEgressCheckInterval)
		}
	}
	if peerUpdate.ServerVersion != config.Version {
		slog.Warn("server/client version mismatch", "server", peerUpdate.ServerVersion, "client", config.Version)
		vlt, err := versionLessThan(config.Version, peerUpdate.ServerVersion)
		if err != nil {
			slog.Error("error checking version less than", "error", err)
			return
		}
		if vlt && peerUpdate.Host.AutoUpdate {
			slog.Info("updating client to server's version", "version", peerUpdate.ServerVersion)
			upgMutex.Lock()
			if err := UseVersion(peerUpdate.ServerVersion, false); err != nil {
				slog.Error("error updating client to server's version", "error", err)
			} else {
				slog.Info("updated client to server's version", "version", peerUpdate.ServerVersion)
				daemon.HardRestart()
			}
			upgMutex.Unlock()
		}
	}
	saveServerConfig := false
	if peerUpdate.ServerVersion != server.Version {
		slog.Info("updating server version", "server", serverName, "version", peerUpdate.ServerVersion)
		server.Version = peerUpdate.ServerVersion
		config.WriteServerConfig()
	}
	if peerUpdate.MetricsPort != 0 && peerUpdate.MetricsPort != server.MetricsPort {
		slog.Info("metrics has changed", "from", server.MetricsPort, "to", peerUpdate.MetricsPort)
		server.MetricsPort = peerUpdate.MetricsPort
		config.WriteServerConfig()
		daemon.Restart()
	}
	if peerUpdate.MetricInterval != server.MetricInterval {
		i, err := strconv.Atoi(peerUpdate.MetricInterval)
		if err == nil {
			metricTicker.Reset(time.Minute * time.Duration(i))
		}
		server.MetricInterval = peerUpdate.MetricInterval

	}
	//get the current default gateway
	ip, err := wireguard.GetDefaultGatewayIp()
	if err != nil {
		slog.Error("error loading current default gateway", "error", err.Error())
		return
	}

	//setup the default gateway when change_default_gw set to true
	if peerUpdate.ChangeDefaultGw {
		//only update if the current gateway ip is not the same as desired
		if !peerUpdate.DefaultGwIp.Equal(ip) {
			if !wireguard.GetIGWMonitor().IsCurrentIGW(ip) {
				var igw wgtypes.PeerConfig
				for _, peer := range peerUpdate.Peers {
					for _, peerIP := range peer.AllowedIPs {
						if peerIP.String() == wireguard.IPv4Network || peerIP.String() == wireguard.IPv6Network {
							igw = peer
							break
						}
					}
				}

				_ = wireguard.RestoreInternetGw()

				err = wireguard.SetInternetGw(igw.PublicKey.String(), peerUpdate.DefaultGwIp)
				if err != nil {
					slog.Error("error setting default gateway", "error", err.Error())
					return
				}
			}
		}
	} else {
		//when change_default_gw set to false, check if it needs to restore to old gateway
		if config.Netclient().OriginalDefaultGatewayIp != nil && !config.Netclient().OriginalDefaultGatewayIp.Equal(ip) && config.Netclient().CurrGwNmIP != nil {
			err = wireguard.RestoreInternetGw()
			if err != nil {
				slog.Error("error restoring default gateway", "error", err.Error())
				return
			}
		}
	}
	if !peerUpdate.ServerConfig.EndpointDetection {
		cache.EndpointCache = sync.Map{}
		cache.SkipEndpointCache = sync.Map{}
	}
	config.UpdateHostPeers(peerUpdate.Peers)
	_ = wireguard.SetPeers(peerUpdate.ReplacePeers)
	if len(peerUpdate.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(peerUpdate.EgressRoutes)
		wireguard.SetEgressRoutesInCache(peerUpdate.EgressRoutes)
	} else {
		wireguard.RemoveEgressRoutes()
		wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{})
	}
	if peerUpdate.ServerConfig.EndpointDetection {
		go handleEndpointDetection(peerUpdate.Peers, peerUpdate.HostNetworkInfo)
	}
	if len(peerUpdate.EgressWithDomains) > 0 {
		wireguard.SetEgressDomains(peerUpdate.EgressWithDomains)
	}
	go CheckEgressDomainUpdates()
	peerUpdate.DnsNameservers = FilterDnsNameservers(peerUpdate.DnsNameservers)
	var dnsOp string
	const start string = "start"
	const stop string = "stop"
	const update string = "update"
	if server.ManageDNS {
		if !peerUpdate.ManageDNS {
			server.ManageDNS = false
			server.DefaultDomain = ""
			server.NameServers = nil
			server.DnsNameservers = nil
			saveServerConfig = true
			dnsOp = stop
		} else if server.DefaultDomain != peerUpdate.DefaultDomain ||
			len(server.DnsNameservers) != len(peerUpdate.DnsNameservers) ||
			!reflect.DeepEqual(server.DnsNameservers, peerUpdate.DnsNameservers) {
			server.DefaultDomain = peerUpdate.DefaultDomain
			server.NameServers = peerUpdate.NameServers
			server.DnsNameservers = peerUpdate.DnsNameservers
			saveServerConfig = true
			dnsOp = update
		}
	} else {
		if peerUpdate.ManageDNS {
			server.ManageDNS = true
			server.DefaultDomain = peerUpdate.DefaultDomain
			server.NameServers = peerUpdate.NameServers
			server.DnsNameservers = peerUpdate.DnsNameservers
			saveServerConfig = true
			dnsOp = start
		}
	}

	reloadStun := false
	if peerUpdate.Stun != server.Stun {
		server.Stun = peerUpdate.Stun
		saveServerConfig = true
		reloadStun = true
	}
	if peerUpdate.StunServers != server.StunServers {
		server.StunServers = peerUpdate.StunServers
		saveServerConfig = true
		reloadStun = true
	}
	if peerUpdate.ServerConfig.IsPro && !server.IsPro {
		server.IsPro = true
		saveServerConfig = true
	}

	if saveServerConfig {
		config.UpdateServer(serverName, *server)
		_ = config.WriteServerConfig()
		switch dnsOp {
		case start:
			dns.GetDNSServerInstance().Start()
		case stop:
			dns.GetDNSServerInstance().Stop()
		case update:
			_ = dns.SetupDNSConfig()
			_ = dns.FlushLocalDnsCache()
		}
	}

	if peerUpdate.Host.EnableFlowLogs {
		_ = flow.GetManager().Start(peerUpdate.AddressIdentityMap)
	} else {
		_ = flow.GetManager().Stop()
	}

	if reloadStun {
		_ = daemon.Restart()
	}
	setAutoRelayNodes(peerUpdate.AutoRelayNodes, peerUpdate.GwNodes, peerUpdate.Nodes)
	handleFwUpdate(serverName, &peerUpdate.FwUpdate)

}

// HostUpdate - mq handler for host update host/update/<HOSTID>/<SERVERNAME>
func HostUpdate(client mqtt.Client, msg mqtt.Message) {
	var hostUpdate models.HostUpdate
	var err error
	writeToDisk := true
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	if len(msg.Payload()) == 0 {
		return
	}
	data, err := decryptAESGCM(config.Netclient().TrafficKeyPublic[0:32], msg.Payload())
	if err != nil {
		slog.Warn("error decrypting message", "warn", err)
		data, err = decryptMsg(server.Name, msg.Payload())
		if err != nil {
			slog.Error("error decrypting message", "error", err)
			return
		}
	} else {
		data, err = unzipPayload(data)
		if err != nil {
			slog.Error("error unzipping message", "error", err)
			return
		}
	}
	err = json.Unmarshal([]byte(data), &hostUpdate)
	if err != nil {
		slog.Error("error unmarshalling host update data", "error", err)
		return
	}
	slog.Info("processing host update", "server", serverName, "action", hostUpdate.Action)
	var resetInterface, restartDaemon, sendHostUpdate, clearMsg bool
	switch hostUpdate.Action {
	case models.Upgrade:
		clearRetainedMsg(client, msg.Topic())
		cv, sv := config.Version, server.Version
		slog.Info("checking if need to upgrade client to server's version", "", config.Version, "version", server.Version)
		vlt, err := versionLessThan(cv, sv)
		if err == nil {
			// if we have an assertive result, and it's that
			// the client is up-to-date, nothing else to do
			if !vlt {
				slog.Info("no need to upgrade client, version is up-to-date")
				break
			}
		} else {
			// if we have a dubious result, assume that we need to upgrade client,
			// this can occur when using custom client versions not following semver
			slog.Warn("error checking version less than, but will proceed with upgrade", "error", err)
		}
		slog.Info("upgrading client to server's version", "version", sv)
		upgMutex.Lock()
		if err := UseVersion(sv, false); err != nil {
			slog.Error("error upgrading client to server's version", "error", err)
		} else {
			slog.Info("upgraded client to server's version, restarting", "version", sv)
			daemon.HardRestart()
		}
		upgMutex.Unlock()
	case models.ForceUpgrade:
		clearRetainedMsg(client, msg.Topic())
		slog.Info("force upgrading client to server's version", "version", server.Version)
		upgMutex.Lock()
		if err := UseVersion(server.Version, false); err != nil {
			slog.Error("error upgrading client to server's version", "error", err)
		} else {
			slog.Info("upgraded client to server's version, restarting", "version", server.Version)
			daemon.HardRestart()
		}
		upgMutex.Unlock()
	case models.JoinHostToNetwork:
		fmt.Println("======> RECEIVED JoinHostToNetwork")
		commonNode := hostUpdate.Node.CommonNode
		nodeCfg := config.Node{
			CommonNode: commonNode,
		}
		config.UpdateNodeMap(hostUpdate.Node.Network, nodeCfg)
		server := config.GetServer(serverName)
		if server == nil {
			return
		}
		server.Nodes[hostUpdate.Node.Network] = true
		config.UpdateServer(serverName, *server)
		config.WriteNodeConfig()
		config.WriteServerConfig()
		slog.Info("added node to network", "network", hostUpdate.Node.Network, "server", serverName)
		clearRetainedMsg(client, msg.Topic()) // clear message before ACK
		if err = PublishHostUpdate(serverName, models.Acknowledgement); err != nil {
			slog.Error("failed to response with ACK to server", "server", serverName, "error", err)
		}
		setSubscriptions(client, &nodeCfg)
		setDNSSubscriptions(client, &nodeCfg, server.Name)
		resetInterface = true
	case models.DeleteHost:
		clearRetainedMsg(client, msg.Topic())
		unsubscribeHost(client, serverName)
		deleteHostCfg(client, serverName)
		config.WriteNodeConfig()
		config.WriteServerConfig()
		config.DeleteClientNodes()
		restartDaemon = true
	case models.UpdateHost:
		resetInterface, restartDaemon, sendHostUpdate = config.UpdateHost(&hostUpdate.Host)
		if sendHostUpdate {
			if err := PublishHostUpdate(config.CurrServer, models.UpdateHost); err != nil {
				slog.Error("could not publish host update", err.Error())
			}
		}
		clearMsg = true
		writeToDisk = false
	case models.RequestAck:
		clearRetainedMsg(client, msg.Topic()) // clear message before ACK
		if err = PublishHostUpdate(serverName, models.Acknowledgement); err != nil {
			slog.Error("failed to response with ACK to server", "server", serverName, "error", err)
		}
		writeToDisk = false
	case models.SignalHost:
		clearRetainedMsg(client, msg.Topic())
		processPeerSignal(hostUpdate.Signal)
		writeToDisk = false
	case models.UpdateKeys:
		clearRetainedMsg(client, msg.Topic()) // clear message
		UpdateKeys()
		writeToDisk = false
	case models.RequestPull:
		clearMsg = true
		restartDaemon = true
		writeToDisk = false
	case models.SignalPull:
		clearRetainedMsg(client, msg.Topic())
		response, resetInterface, replacePeers, err := Pull(false, false)
		if err != nil {
			slog.Error("pull failed", "error", err)
		} else {
			mqFallbackPull(response, resetInterface, replacePeers)
		}
		writeToDisk = false
	case models.EgressUpdate:

		slog.Info("processing egress update", "domain", hostUpdate.EgressDomain.Domain)
		go processEgressDomain(hostUpdate.EgressDomain, true)
	case models.CheckAutoAssignGw:
		checkAssignGw(server, hostUpdate.Node)
	default:
		slog.Error("unknown host action", "action", hostUpdate.Action)
		return
	}
	if writeToDisk {
		if err = config.WriteNetclientConfig(); err != nil {
			slog.Error("failed to write host config", "error", err)
			return
		}
	}
	if restartDaemon {
		if clearMsg {
			clearRetainedMsg(client, msg.Topic())
		}
		if err := daemon.Restart(); err != nil {
			slog.Error("failed to restart daemon", "error", err)
		}
		return
	}
	if resetInterface {
		resetInterfaceFunc()
	}
}

func resetInterfaceFunc() {
	mNMutex.Lock()
	defer mNMutex.Unlock()
	nc := wireguard.GetInterface()
	nc.Close()
	nc = wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	nc.Create()
	if err := nc.Configure(); err != nil {
		slog.Error("could not configure netmaker interface", "error", err)
		return
	}
	if err := wireguard.SetPeers(false); err != nil {
		slog.Error("failed to set peers", err)
	}
	wireguard.SetRoutesFromCache()

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	if server.ManageDNS {
		// if dns.GetDNSServerInstance().AddrStr == "" {
		// 	dns.GetDNSServerInstance().Monitor()
		// }

		//Setup DNS for Linux and Windows
		if config.Netclient().Host.OS == "linux" || config.Netclient().Host.OS == "windows" {
			dns.GetDNSServerInstance().Stop()
			dns.GetDNSServerInstance().Start()
		}
	}
	wireguard.EgressResetCh <- struct{}{}
}

// handleEndpointDetection - select best interface for each peer and set it as endpoint
func handleEndpointDetection(peers []wgtypes.PeerConfig, peerInfo models.HostInfoMap) {
	currentCidrs := getAllAllowedIPs(peers[:])
	metricPort := config.GetServer(config.CurrServer).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for idx := range peers {
		peerPubKey := peers[idx].PublicKey.String()
		if wireguard.EndpointDetectedAlready(peerPubKey) {
			continue
		}
		// check if endpoint detection to be skipped for the peer
		if retryCnt, ok := cache.SkipEndpointCache.Load(peerPubKey); ok {
			if retryCnt.(int) > 3 {
				continue
			}
		}
		if peerInfo, ok := peerInfo[peerPubKey]; ok {
			// if peerInfo.IsStatic {
			// 	// peer is a static host shouldn't disturb the configuration set by the user
			// 	continue
			// }
			for i := range peerInfo.Interfaces {
				peerIface := peerInfo.Interfaces[i]
				peerIP := peerIface.Address.IP
				if peerIP == nil {
					continue
				}
				// check to skip bridge network
				if ncutils.IsBridgeNetwork(peerIface.Name) {
					continue
				}
				if strings.Contains(peerIP.String(), "127.0.0.") ||
					peerIP.IsMulticast() ||
					(peerIP.IsLinkLocalUnicast() && strings.Count(peerIP.String(), ":") >= 2) ||
					isAddressInPeers(peerIP, currentCidrs) {
					continue
				}
				if peerIP.IsPrivate() {
					go func(peerIP, peerPubKey string, listenPort int) {
						networking.FindBestEndpoint(
							peerIP,
							peerPubKey,
							listenPort,
							metricPort,
						)
					}(peerIP.String(), peerPubKey, peerInfo.ListenPort)

				}
			}
		}
	}
}

func deleteHostCfg(client mqtt.Client, server string) {
	config.DeleteServerHostPeerCfg()
	nodes := config.GetNodes()
	for k, node := range nodes {
		node := node
		if node.Server == server {
			unsubscribeNode(client, &node)
			config.DeleteNode(k)
		}
	}
	config.DeleteServer(server)
}

func parseNetworkFromTopic(topic string) string {
	return strings.Split(topic, "/")[2]
}

func parseServerFromTopic(topic string) string {
	return strings.Split(topic, "/")[3]
}

func getAllAllowedIPs(peers []wgtypes.PeerConfig) (cidrs []net.IPNet) {
	if len(peers) > 0 { // nil check
		for i := range peers {
			peer := peers[i]
			cidrs = append(cidrs, peer.AllowedIPs...)
		}
	}
	if cidrs == nil {
		cidrs = []net.IPNet{}
	}
	return
}

func isAddressInPeers(ip net.IP, cidrs []net.IPNet) bool {
	if len(cidrs) > 0 {
		for i := range cidrs {
			currCidr := cidrs[i]
			if currCidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func handleFwUpdate(server string, payload *models.FwUpdate) {

	if payload.IsEgressGw {
		firewall.SetEgressRoutes(server, payload.EgressInfo)
	} else {
		firewall.DeleteEgressGwRoutes(server)
	}
	if payload.IsIngressGw {
		firewall.ProcessIngressUpdate(server, payload.IngressInfo)
	} else {
		firewall.RemoveIngressRoutingRules(server)
	}
	firewall.ProcessAclRules(server, payload)

}

func getServerBrokerStatus() (bool, error) {

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return false, errors.New("server is nil")
	}
	var status map[string]interface{}
	url := fmt.Sprintf("https://%s/api/server/status", server.API)
	endpoint := httpclient.JSONEndpoint[map[string]interface{}, models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Data:          nil,
		Response:      status,
		ErrorResponse: models.ErrorResponse{},
	}
	response, errData, err := endpoint.GetJSON(status, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "status error calling ", endpoint.URL, errData.Message)
			return false, err
		}
		logger.Log(1, "failed to read from server during metrics publish", err.Error())
		return false, err
	}

	if _, ok := response["is_broker_conn_open"]; ok {
		return response["is_broker_conn_open"].(bool), nil
	}

	return response["broker_connected"].(bool), nil
}

// MQTT Fallback Mechanism
func mqFallback(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	mqFallbackTicker := time.NewTicker(time.Second * 30)
	for {
		select {
		case <-ctx.Done():
			mqFallbackTicker.Stop()
			slog.Info("mqfallback routine stop")
			return
		case <-mqFallbackTicker.C: // Execute pull every 30 seconds
			skip := true
			if connected, err := getServerBrokerStatus(); err == nil && !connected {
				skip = false
			}
			if skip && ((Mqclient != nil && Mqclient.IsConnectionOpen() && Mqclient.IsConnected()) || config.CurrServer == "") {
				continue
			}
			// Call netclient http config pull
			slog.Info("### mqfallback routine execute")
			auth.CleanJwtToken()
			response, resetInterface, replacePeers, err := Pull(false, false)
			if err != nil {
				slog.Error("pull failed", "error", err)
			} else {
				mqFallbackPull(response, resetInterface, replacePeers)
				server := config.GetServer(config.CurrServer)
				if server == nil {
					continue
				}
				slog.Info("re-attempt mqtt connection after pull")
				if Mqclient != nil {
					Mqclient.Disconnect(0)
				}
				if err := setupMQTT(server); err != nil {
					slog.Error("unable to connect to broker", "server", server.Broker, "error", err)
				}
			}

		}
	}
}

// MQTT Fallback Config Pull
func mqFallbackPull(pullResponse models.HostPull, resetInterface, replacePeers bool) {
	serverName := config.CurrServer
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	if pullResponse.ServerConfig.Version != config.Version {
		slog.Warn("server/client version mismatch", "server", pullResponse.ServerConfig.Version, "client", config.Version)
		vlt, err := versionLessThan(config.Version, pullResponse.ServerConfig.Version)
		if err != nil {
			slog.Error("error checking version less than", "error", err)
			return
		}
		if vlt && config.Netclient().Host.AutoUpdate {
			slog.Info("updating client to server's version", "version", pullResponse.ServerConfig.Version)
			upgMutex.Lock()
			if err := UseVersion(pullResponse.ServerConfig.Version, false); err != nil {
				slog.Error("error updating client to server's version", "error", err)
			} else {
				slog.Info("updated client to server's version", "version", pullResponse.ServerConfig.Version)
				daemon.HardRestart()
			}
			upgMutex.Unlock()
		}
	}
	if pullResponse.ServerConfig.Version != server.Version {
		slog.Info("updating server version", "server", serverName, "version", pullResponse.ServerConfig.Version)
		server.Version = pullResponse.ServerConfig.Version
		config.WriteServerConfig()
	}
	if pullResponse.ServerConfig.MetricsPort != 0 && pullResponse.ServerConfig.MetricsPort != server.MetricsPort {
		slog.Info("metrics has changed", "from", server.MetricsPort, "to", pullResponse.ServerConfig.MetricsPort)
		server.MetricsPort = pullResponse.ServerConfig.MetricsPort
		config.WriteServerConfig()
		daemon.Restart()
	}
	//get the current default gateway
	ip, err := wireguard.GetDefaultGatewayIp()
	if err != nil {
		slog.Error("error loading current default gateway", "error", err.Error())
		return
	}

	//setup the default gateway when change_default_gw set to true
	if pullResponse.ChangeDefaultGw {
		//only update if the current gateway ip is not the same as desired
		if !pullResponse.DefaultGwIp.Equal(ip) {
			if !wireguard.GetIGWMonitor().IsCurrentIGW(ip) {
				var igw wgtypes.PeerConfig
				for _, peer := range pullResponse.Peers {
					for _, peerIP := range peer.AllowedIPs {
						if peerIP.String() == wireguard.IPv4Network || peerIP.String() == wireguard.IPv6Network {
							igw = peer
							break
						}
					}
				}

				_ = wireguard.RestoreInternetGw()

				err = wireguard.SetInternetGw(igw.PublicKey.String(), pullResponse.DefaultGwIp)
				if err != nil {
					slog.Error("error setting default gateway", "error", err.Error())
					return
				}
			}
		}
	} else {
		//when change_default_gw set to false, check if it needs to restore to old gateway
		if config.Netclient().OriginalDefaultGatewayIp != nil && !config.Netclient().OriginalDefaultGatewayIp.Equal(ip) && config.Netclient().CurrGwNmIP != nil {
			err = wireguard.RestoreInternetGw()
			if err != nil {
				slog.Error("error restoring default gateway", "error", err.Error())
				return
			}
		}
	}
	if !pullResponse.ServerConfig.EndpointDetection {
		cache.EndpointCache = sync.Map{}
		cache.SkipEndpointCache = sync.Map{}
	}
	config.UpdateHostPeers(pullResponse.Peers)
	_ = wireguard.SetPeers(pullResponse.ReplacePeers)
	if len(pullResponse.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pullResponse.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pullResponse.EgressRoutes)
	} else {
		wireguard.RemoveEgressRoutes()
		wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{})
	}
	if pullResponse.ServerConfig.EndpointDetection {
		go handleEndpointDetection(pullResponse.Peers, pullResponse.HostNetworkInfo)
	}
	if len(pullResponse.EgressWithDomains) > 0 {
		wireguard.SetEgressDomains(pullResponse.EgressWithDomains)
	}
	go CheckEgressDomainUpdates()
	pullResponse.DnsNameservers = FilterDnsNameservers(pullResponse.DnsNameservers)
	var saveServerConfig bool
	if len(server.NameServers) != len(pullResponse.NameServers) || reflect.DeepEqual(server.NameServers, pullResponse.NameServers) {
		server.NameServers = pullResponse.NameServers
		saveServerConfig = true
	}

	if len(server.DnsNameservers) != len(pullResponse.DnsNameservers) || reflect.DeepEqual(server.DnsNameservers, pullResponse.DnsNameservers) {
		server.DnsNameservers = pullResponse.DnsNameservers
		saveServerConfig = true
	}

	if pullResponse.ServerConfig.ManageDNS != server.ManageDNS {
		server.ManageDNS = pullResponse.ServerConfig.ManageDNS
		saveServerConfig = true
		if pullResponse.ServerConfig.ManageDNS {
			dns.GetDNSServerInstance().Start()
		} else {
			dns.GetDNSServerInstance().Stop()
		}
	}

	if server.ManageDNS {
		if (config.Netclient().Host.OS == "linux" && dns.GetDNSServerInstance().AddrStr != "" && config.Netclient().DNSManagerType == dns.DNS_MANAGER_STUB) ||
			config.Netclient().Host.OS == "windows" {
			_ = dns.SetupDNSConfig()
			_ = dns.FlushLocalDnsCache()
		}
	}

	reloadStun := false
	if pullResponse.ServerConfig.Stun != server.Stun {
		server.Stun = pullResponse.ServerConfig.Stun
		saveServerConfig = true
		reloadStun = true
	}
	if pullResponse.ServerConfig.StunServers != server.StunServers {
		server.StunServers = pullResponse.ServerConfig.StunServers
		saveServerConfig = true
		reloadStun = true
	}
	if pullResponse.ServerConfig.IsPro && !server.IsPro {
		server.IsPro = true
		saveServerConfig = true
	}

	if reloadStun {
		daemon.Restart()
	}

	if pullResponse.Host.EnableFlowLogs {
		_ = flow.GetManager().Start(pullResponse.AddressIdentityMap)
	} else {
		_ = flow.GetManager().Stop()
	}

	if saveServerConfig {
		config.UpdateServer(serverName, *server)
		_ = config.WriteServerConfig()
	}

	handleFwUpdate(serverName, &pullResponse.FwUpdate)
}

func CheckEgressDomainUpdates() {
	slog.Debug("checking egress domain updates")

	egressDomains := wireguard.GetEgressDomains()
	if len(egressDomains) == 0 {
		slog.Debug("no egress domains to process")
		return
	}

	slog.Info("processing egress domains", "count", len(egressDomains))
	for _, domainI := range egressDomains {
		slog.Debug("checking egress domain", "domain", domainI.Domain)
		processEgressDomain(domainI, false)
	}
}

func processEgressDomain(domainI models.EgressDomain, forceUpdate bool) {
	slog.Info("processing egress domain", "domain", domainI.Domain)

	// Resolve domain to IP addresses
	ips, err := resolveDomainToIPs(domainI.Domain)
	if err != nil {
		slog.Error("failed to resolve egress domain", "domain", domainI.Domain, "error", err)
		return
	}
	if len(ips) == 0 {
		slog.Warn("no IP addresses resolved for domain", "domain", domainI.Domain)
		return
	}

	// Get current cached IPs for this domain
	currentIps := wireguard.GetDomainAnsFromCache(domainI)
	slog.Debug("domain resolution check", "domain", domainI.Domain, "domain_id", domainI.ID, "cached_ips", currentIps, "resolved_ips", ips)

	// Check if there are any changes
	hasChanges := false
	shouldUpdateCache := false

	if len(currentIps) == 0 {
		// First time processing this domain or cache miss
		hasChanges = true
		shouldUpdateCache = true
		slog.Info("first time processing domain or cache miss", "domain", domainI.Domain, "ips", ips)
	} else {
		// Compare current and new IPs
		slices.Sort(currentIps)
		slices.Sort(ips)
		if !slices.Equal(currentIps, ips) {
			hasChanges = true
			slog.Info("domain IPs changed", "domain", domainI.Domain, "old_ips", currentIps, "new_ips", ips)

			// Check if old IPs are still reachable before updating cache
			oldIPsReachable := checkIPConnectivity(currentIps)
			if !oldIPsReachable {
				shouldUpdateCache = true
				slog.Info("old IPs are not reachable, updating cache with new IPs", "domain", domainI.Domain, "old_ips", currentIps, "new_ips", ips)
			} else {
				slog.Info("old IPs are still reachable, keeping current cache to maintain stability", "domain", domainI.Domain, "old_ips", currentIps)
			}
		} else {
			slog.Debug("no changes detected for domain", "domain", domainI.Domain, "ips", ips)
		}
	}
	if !forceUpdate {
		// Only proceed if there are changes and we should update the cache
		if !hasChanges || !shouldUpdateCache {
			if !hasChanges {
				slog.Debug("skipping server update - no changes detected", "domain", domainI.Domain)
			} else {
				slog.Debug("skipping server update - old IPs are still reachable", "domain", domainI.Domain)
			}
			return
		}
	}
	// Update the cache with new IPs only after confirming changes and connectivity check
	wireguard.SetDomainAnsInCache(domainI, ips)
	// Clear existing ranges and add new ones
	domainI.Node.EgressGatewayRanges = []string{}
	for _, ip := range ips {
		// Add as /32 for IPv4 or /128 for IPv6
		if net.ParseIP(ip).To4() != nil {
			domainI.Node.EgressGatewayRanges = append(domainI.Node.EgressGatewayRanges, ip+"/32")
		} else {
			domainI.Node.EgressGatewayRanges = append(domainI.Node.EgressGatewayRanges, ip+"/128")
		}
	}

	slog.Info("sending egress domain update to server", "domain", domainI.Domain, "ips", ips, "ranges", domainI.Node.EgressGatewayRanges)

	// Send the updated host info back to server
	hostServerUpdate(models.HostUpdate{
		Action:       models.EgressUpdate,
		Host:         domainI.Host,
		Node:         domainI.Node,
		EgressDomain: domainI,
	})
}

// checkIPConnectivity checks if all of the given IP addresses are reachable
func checkIPConnectivity(ips []string) bool {
	if len(ips) == 0 {
		return false
	}

	// Check connectivity for each IP - ALL must be reachable
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			slog.Debug("invalid IP address", "ip", ipStr)
			return false
		}

		ipReachable := false

		// Use a simple TCP connection test to check reachability
		// Try common ports that might be open (80, 443, 22)
		ports := []int{80, 443, 22}
		for _, port := range ports {
			address := fmt.Sprintf("%s:%d", ipStr, port)
			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err == nil {
				conn.Close()
				slog.Debug("IP is reachable", "ip", ipStr, "port", port)
				ipReachable = true
				break
			}
		}

		// If TCP connection fails, try ICMP ping for external IPs
		if !ipReachable {
			// Use the existing ping functionality from metrics package
			connected, _ := metrics.ExtPeerConnStatus(ipStr, 3)
			if connected {
				slog.Debug("IP is reachable via ping", "ip", ipStr)
				ipReachable = true
			}
		}

		// If this IP is not reachable, fail the entire check
		if !ipReachable {
			slog.Debug("IP is not reachable", "ip", ipStr)
			return false
		}
	}

	slog.Debug("all IPs are reachable", "ips", ips)
	return true
}

// resolveDomainToIPs resolves a domain name to IP addresses using the existing DNS infrastructure
func resolveDomainToIPs(domain string) ([]string, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Use the existing DNS infrastructure to resolve the domain
	ips := dns.FindDnsAns(domain)
	if len(ips) == 0 {
		lookUpIPs, err := net.LookupIP(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
		}
		if len(lookUpIPs) == 0 {
			return nil, fmt.Errorf("no IP addresses found for domain %s", domain)
		}
		ips = lookUpIPs
	}

	// Filter out any invalid IPs and return unique IPs
	uniqueIPs := make(map[string]string)
	for _, ip := range ips {
		if ip != nil {
			uniqueIPs[ip.String()] = ip.String()
		}
	}

	result := make([]string, 0, len(uniqueIPs))
	for _, ip := range uniqueIPs {
		result = append(result, ip)
	}

	return result, nil
}
