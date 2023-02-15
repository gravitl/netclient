package functions

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/txeh"
)

// MQTimeout - time out for mqtt connections
const MQTimeout = 30

// All -- mqtt message hander for all ('#') topics
var All mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	logger.Log(0, "default message handler -- received message but not handling")
	logger.Log(0, "topic: "+string(msg.Topic()))
}

// NodeUpdate -- mqtt message handler for /update/<NodeID> topic
func NodeUpdate(client mqtt.Client, msg mqtt.Message) {
	network := parseNetworkFromTopic(msg.Topic())
	logger.Log(0, "processing node update for network", network)
	node := config.GetNode(network)
	server := config.Servers[node.Server]
	data, err := decryptMsg(server.Name, msg.Payload())
	if err != nil {
		logger.Log(0, "error decrypting message", err.Error())
		return
	}
	serverNode := models.Node{}
	if err = json.Unmarshal([]byte(data), &serverNode); err != nil {
		logger.Log(0, "error unmarshalling node update data"+err.Error())
		return
	}
	newNode := config.Node{}
	newNode.CommonNode = serverNode.CommonNode

	// see if cache hit, if so skip
	var currentMessage = read(newNode.Network, lastNodeUpdate)
	if currentMessage == string(data) {
		logger.Log(3, "cache hit on node update ... skipping")
		return
	}
	insert(newNode.Network, lastNodeUpdate, string(data)) // store new message in cache
	logger.Log(0, "network:", newNode.Network, "received message to update node "+newNode.ID.String())
	// check if interface needs to delta
	ifaceDelta := wireguard.IfaceDelta(&node, &newNode)
	keepaliveChange := node.PersistentKeepalive != newNode.PersistentKeepalive
	//nodeCfg.Node = newNode
	switch newNode.Action {
	case models.NODE_DELETE:
		logger.Log(0, "network:", newNode.Network, " received delete request for %s", newNode.ID.String())
		unsubscribeNode(client, &newNode)
		if _, err = LeaveNetwork(newNode.Network, true); err != nil {
			if !strings.Contains("rpc error", err.Error()) {
				logger.Log(0, "failed to leave, please check that local files for network", newNode.Network, "were removed")
				return
			}
		}
		logger.Log(0, newNode.ID.String(), "was removed from network", newNode.Network)
		return
	case models.NODE_UPDATE_KEY:
		// == get the current key for node ==
		oldPrivateKey := config.Netclient().PrivateKey
		if err := UpdateKeys(&newNode, config.Netclient(), client); err != nil {
			logger.Log(0, "err updating wireguard keys, reusing last key\n", err.Error())
			config.Netclient().PrivateKey = oldPrivateKey
		}
		config.Netclient().PublicKey = config.Netclient().PrivateKey.PublicKey()
		ifaceDelta = true
	case models.NODE_FORCE_UPDATE:
		ifaceDelta = true
	case models.NODE_NOOP:
	default:
	}
	// Save new config
	newNode.Action = models.NODE_NOOP
	config.UpdateNodeMap(network, newNode)
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, newNode.Network, "error updating node configuration: ", err.Error())
	}
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	if err := nc.Configure(); err != nil {
		logger.Log(0, "could not configure netmaker interface", err.Error())
		return
	}

	wireguard.SetPeers()
	if err := wireguard.UpdateWgInterface(&newNode, config.Netclient()); err != nil {

		logger.Log(0, "error updating wireguard config "+err.Error())
		return
	}
	if keepaliveChange {
		wireguard.UpdateKeepAlive(int(newNode.PersistentKeepalive.Seconds()))
	}
	time.Sleep(time.Second)
	if ifaceDelta { // if a change caused an ifacedelta we need to notify the server to update the peers
		doneErr := publishSignal(&newNode, DONE)
		if doneErr != nil {
			logger.Log(0, "network:", newNode.Network, "could not notify server to update peers after interface change")
		} else {
			logger.Log(0, "network:", newNode.Network, "signalled finished interface update to server")
		}
	}
}

// HostPeerUpdate - mq handler for host peer update peers/host/<HOSTID>/<SERVERNAME>
func HostPeerUpdate(client mqtt.Client, msg mqtt.Message) {
	var peerUpdate models.HostPeerUpdate
	var err error
	if len(config.GetNodes()) == 0 {
		logger.Log(3, "skipping unwanted peer update, no nodes exist")
		return
	}
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		logger.Log(0, "server ", serverName, " not found in config")
		return
	}
	logger.Log(3, "received peer update for host from: ", serverName)
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(data), &peerUpdate)
	if err != nil {
		logger.Log(0, "error unmarshalling peer data")
		return
	}
	if peerUpdate.ServerVersion != config.Version {
		logger.Log(0, "server/client version mismatch server: ", peerUpdate.ServerVersion, " client: ", config.Version)
	}
	if peerUpdate.ServerVersion != server.Version {
		logger.Log(1, "updating server version")
		server.Version = peerUpdate.ServerVersion
		config.WriteServerConfig()
	}
	_, err = wireguard.UpdateWgPeers(peerUpdate.Peers)
	if err != nil {
		logger.Log(0, "error updating wireguard peers"+err.Error())
		return
	}

	config.UpdateHostPeers(serverName, peerUpdate.Peers)
	config.WriteNetclientConfig()
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	nc.Configure()
	wireguard.SetPeers()
	if config.Netclient().ProxyEnabled {
		time.Sleep(time.Second * 2) // sleep required to avoid race condition
		peerUpdate.ProxyUpdate.Action = models.ProxyUpdate
	} else {
		peerUpdate.ProxyUpdate.Action = models.NoProxy
	}
	peerUpdate.ProxyUpdate.Server = serverName
	ProxyManagerChan <- &peerUpdate
}

// HostUpdate - mq handler for host update host/update/<HOSTID>/<SERVERNAME>
func HostUpdate(client mqtt.Client, msg mqtt.Message) {
	var hostUpdate models.HostUpdate
	var err error
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		logger.Log(0, "server ", serverName, " not found in config")
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(data), &hostUpdate)
	if err != nil {
		logger.Log(0, "error unmarshalling host update data")
		return
	}
	logger.Log(3, fmt.Sprintf("---> received host update [ action: %v ] for host from %s ", hostUpdate.Action, serverName))
	var resetInterface, restartDaemon bool
	switch hostUpdate.Action {
	case models.JoinHostToNetwork:
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
		restartDaemon = true
	case models.DeleteHost:
		clearRetainedMsg(client, msg.Topic())
		unsubscribeHost(client, serverName)
		deleteHostCfg(client, serverName)
		config.WriteNodeConfig()
		config.WriteServerConfig()
		resetInterface = true
	case models.UpdateHost:
		resetInterface, restartDaemon = updateHostConfig(&hostUpdate.Host)
	default:
		logger.Log(1, "unknown host action")
		return
	}
	if err = config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "failed to write host config -", err.Error())
		return
	}

	if restartDaemon {
		clearRetainedMsg(client, msg.Topic())
		if err := daemon.Restart(); err != nil {
			logger.Log(0, "failed to restart daemon: ", err.Error())
		}
		return
	}
	if resetInterface {
		nc := wireguard.GetInterface()
		nc.Close()
		nc = wireguard.NewNCIface(config.Netclient(), config.GetNodes())
		nc.Create()
		if err := nc.Configure(); err != nil {
			logger.Log(0, "could not configure netmaker interface", err.Error())
			return
		}
		wireguard.SetPeers()
	}

}

func deleteHostCfg(client mqtt.Client, server string) {
	config.DeleteServerHostPeerCfg(server)
	nodes := config.GetNodes()
	for k, node := range nodes {
		node := node
		if node.Server == server {
			unsubscribeNode(client, &node)
			config.DeleteNode(k)
		}
	}
	config.DeleteServer(server)
	// delete mq client from ServerSet map
	delete(ServerSet, server)
}

func updateHostConfig(host *models.Host) (resetInterface, restart bool) {
	hostCfg := config.Netclient()
	if hostCfg == nil || host == nil {
		return
	}
	if hostCfg.ListenPort != host.ListenPort || hostCfg.ProxyListenPort != host.ProxyListenPort {
		restart = true
	}
	if hostCfg.MTU != host.MTU {
		resetInterface = true
	}
	// store password before updating
	host.HostPass = hostCfg.HostPass
	hostCfg.Host = *host
	config.UpdateNetclient(*hostCfg)
	config.WriteNetclientConfig()
	return
}

func parseNetworkFromTopic(topic string) string {
	return strings.Split(topic, "/")[2]
}

func parseServerFromTopic(topic string) string {
	return strings.Split(topic, "/")[3]
}

// dnsUpdate - mq handler for host update dns/<HOSTID>/server
func dnsUpdate(client mqtt.Client, msg mqtt.Message) {
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if err := config.Lock(lockfile); err != nil {
		logger.Log(0, "could not create lock file", err.Error())
		return
	}
	defer config.Unlock(lockfile)
	var dns models.DNSUpdate
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		logger.Log(0, "server ", serverName, " not found in config")
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	if err := json.Unmarshal([]byte(data), &dns); err != nil {
		logger.Log(0, "error unmarshalling dns update")
	}
	if config.Netclient().Debug {
		log.Println("dnsUpdate received", dns)
	}
	var currentMessage = read("dns", lastDNSUpdate)
	if currentMessage == string(data) {
		logger.Log(3, "cache hit on dns update ... skipping")
		return
	}
	insert("dns", lastDNSUpdate, string(data))
	logger.Log(3, "received dns update for", dns.Name)
	applyDNSUpdate(dns)
}

func applyDNSUpdate(dns models.DNSUpdate) {
	if config.Netclient().Debug {
		log.Println(dns)
	}
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		logger.Log(0, "failed to read hosts file", err.Error())
		return
	}
	switch dns.Action {
	case models.DNSInsert:
		hosts.AddHost(dns.Address, dns.Name, etcHostsComment)
	case models.DNSDeleteByName:
		hosts.RemoveHost(dns.Name, etcHostsComment)
	case models.DNSDeleteByIP:
		hosts.RemoveAddress(dns.Address, etcHostsComment)
	case models.DNSReplaceName:
		ok, ip, _ := hosts.HostAddressLookup(dns.Name, etcHostsComment)
		if !ok {
			logger.Log(2, "failed to find dns address for host", dns.Name)
			return
		}
		dns.Address = ip
		hosts.RemoveHost(dns.Name, etcHostsComment)
		hosts.AddHost(dns.Address, dns.NewName, etcHostsComment)
	case models.DNSReplaceIP:
		hosts.RemoveAddress(dns.Address, etcHostsComment)
		hosts.AddHost(dns.NewAddress, dns.Name, etcHostsComment)
	}
	if err := hosts.Save(); err != nil {
		logger.Log(0, "error saving hosts file", err.Error())
		return
	}
}

// dnsAll- mq handler for host update dnsall/<HOSTID>/server
func dnsAll(client mqtt.Client, msg mqtt.Message) {
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if err := config.Lock(lockfile); err != nil {
		logger.Log(0, "could not create lock file", err.Error())
		return
	}
	defer config.Unlock(lockfile)
	var dns []models.DNSUpdate
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		logger.Log(0, "server ", serverName, " not found in config")
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	if err := json.Unmarshal([]byte(data), &dns); err != nil {
		logger.Log(0, "error unmarshalling dns update")
	}
	if config.Netclient().Debug {
		log.Println("all dns", dns)
	}
	var currentMessage = read("dnsall", lastALLDNSUpdate)
	logger.Log(3, "received initial dns")
	if currentMessage == string(data) {
		logger.Log(3, "cache hit on all dns ... skipping")
		if config.Netclient().Debug {
			log.Println("dns cache", currentMessage, string(data))
		}
		return
	}
	insert("dnsall", lastALLDNSUpdate, string(data))
	applyAllDNS(dns)
}

func applyAllDNS(dns []models.DNSUpdate) {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		logger.Log(0, "failed to read hosts file", err.Error())
		return
	}
	for _, entry := range dns {
		if entry.Action != models.DNSInsert {
			logger.Log(0, "invalid dns actions", entry.Action.String())
			continue
		}
		hosts.AddHost(entry.Address, entry.Name, etcHostsComment)
	}

	if err := hosts.Save(); err != nil {
		logger.Log(0, "error saving hosts file", err.Error())
		return
	}
}
