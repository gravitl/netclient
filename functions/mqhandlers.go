package functions

import (
	"encoding/json"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	proxy_models "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
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
	shouldDNSChange := node.DNSOn != newNode.DNSOn
	keepaliveChange := node.PersistentKeepalive != newNode.PersistentKeepalive
	//nodeCfg.Node = newNode
	switch newNode.Action {
	case models.NODE_DELETE:
		logger.Log(0, "network:", newNode.Network, " received delete request for %s", newNode.ID.String())
		unsubscribeNode(client, &newNode)
		if _, err = LeaveNetwork(newNode.Network); err != nil {
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
	//deal with DNS
	if newNode.DNSOn && shouldDNSChange {
		logger.Log(0, "network:", newNode.Network, "settng DNS off")
		if err := removeHostDNS(newNode.Network); err != nil {
			logger.Log(0, "network:", newNode.Network, "error removing netmaker profile from /etc/hosts "+err.Error())
		}
		//		_, err := ncutils.RunCmd("/usr/bin/resolvectl revert "+nodeCfg.Node.Interface, true)
		//		if err != nil {
		//			logger.Log(0, "error applying dns" + err.Error())
		//		}
	}
	_ = UpdateLocalListenPort(&newNode)
}

// HostPeerUpdate - mq handler for host peer update peers/host/<HOSTID>/<SERVERNAME>
func HostPeerUpdate(client mqtt.Client, msg mqtt.Message) {
	var peerUpdate models.HostPeerUpdate
	var err error
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
	internetGateway, err := wireguard.UpdateWgPeers(peerUpdate.Peers)
	if err != nil {
		logger.Log(0, "error updating wireguard peers"+err.Error())
		return
	}
	config.Netclient().ProxyEnabled = peerUpdate.Host.ProxyEnabled
	config.UpdateHostPeers(serverName, peerUpdate.Peers)
	config.WriteNetclientConfig()
	wireguard.SetPeers()

	if config.Netclient().ProxyEnabled {
		time.Sleep(time.Second * 2) // sleep required to avoid race condition
		peerUpdate.ProxyUpdate.Server = serverName
		ProxyManagerChan <- &peerUpdate
	} else {
		peerUpdate.ProxyUpdate.Action = proxy_models.NoProxy
		ProxyManagerChan <- &peerUpdate
	}

	for network, networkInfo := range peerUpdate.Network {
		//check if internet gateway has changed
		node := config.GetNode(network)
		oldGateway := node.InternetGateway
		if (internetGateway == nil && oldGateway != nil) || (internetGateway != nil && internetGateway.String() != oldGateway.String()) {
			node.InternetGateway = internetGateway
			config.UpdateNodeMap(node.Network, node)
			if err := config.WriteNodeConfig(); err != nil {
				logger.Log(0, "failed to save internet gateway", err.Error())
			}
		}
		logger.Log(0, "network:", node.Network, "received peer update for node "+node.ID.String()+" "+node.Network)
		if node.DNSOn {
			if err := setHostDNS(networkInfo.DNS, node.Network); err != nil {
				logger.Log(0, "network:", node.Network, "error updating /etc/hosts "+err.Error())
				return
			}
		} else {
			if err := removeHostDNS(node.Network); err != nil {
				logger.Log(0, "network:", node.Network, "error removing profile from /etc/hosts "+err.Error())
				return
			}
		}
		UpdateLocalListenPort(&node)
	}

}

func parseNetworkFromTopic(topic string) string {
	return strings.Split(topic, "/")[1]
}

func parseServerFromTopic(topic string) string {
	return strings.Split(topic, "/")[3]
}
