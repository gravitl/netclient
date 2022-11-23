package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/guumaster/hostctl/pkg/file"
	"github.com/guumaster/hostctl/pkg/parser"
	"github.com/guumaster/hostctl/pkg/types"
)

// MQTimeout - time out for mqtt connections
const MQTimeout = 30

// All -- mqtt message hander for all ('#') topics
var All mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	logger.Log(0, "default message handler -- received message but not handling")
	logger.Log(0, "topic: "+string(msg.Topic()))
	//logger.Log(0, "Message: " + string(msg.Payload()))
}

// NodeUpdate -- mqtt message handler for /update/<NodeID> topic
func NodeUpdate(client mqtt.Client, msg mqtt.Message) {
	network := parseNetworkFromTopic(msg.Topic())
	logger.Log(0, "processing node update for network", network)
	node := config.GetNode(network)
	//server := config.Servers[node.Server]
	data, err := decryptMsg(&node, msg.Payload())
	if err != nil {
		logger.Log(0, "error decrypting message", err.Error())
		return
	}
	nodeUpdate := models.Node{}
	if err = json.Unmarshal([]byte(data), &nodeUpdate); err != nil {
		logger.Log(0, "error unmarshalling node update data"+err.Error())
		return
	}

	// see if cache hit, if so skip
	var currentMessage = read(nodeUpdate.Network, lastNodeUpdate)
	if currentMessage == string(data) {
		logger.Log(3, "cache hit on node update ... skipping")
		return
	}
	var nodeGet models.NodeGet
	nodeGet.Node = nodeUpdate
	for _, wgnode := range config.GetNodes() {
		nodeGet.Peers = append(nodeGet.Peers, wgnode.Peers...)
	}
	newNode, _, _ := config.ConvertNode(&nodeGet)
	insert(newNode.Network, lastNodeUpdate, string(data)) // store new message in cache
	logger.Log(0, "network:", newNode.Network, "received message to update node "+newNode.ID)

	// check if interface needs to delta
	ifaceDelta := wireguard.IfaceDelta(&node, newNode)
	shouldDNSChange := node.DNSOn != newNode.DNSOn
	hubChange := node.IsHub != newNode.IsHub
	keepaliveChange := node.PersistentKeepalive != newNode.PersistentKeepalive

	//nodeCfg.Node = newNode
	switch newNode.Action {
	case models.NODE_DELETE:
		logger.Log(0, "network:", newNode.Network, " received delete request for %s", newNode.ID)
		unsubscribeNode(client, newNode)
		if _, err = LeaveNetwork(newNode.Network); err != nil {
			if !strings.Contains("rpc error", err.Error()) {
				logger.Log(0, "failed to leave, please check that local files for network", newNode.Network, "were removed")
				return
			}
		}
		logger.Log(0, newNode.ID, "was removed from network", newNode.Network)
		return
	case models.NODE_UPDATE_KEY:
		// == get the current key for node ==
		oldPrivateKey := config.Netclient().PrivateKey
		if err := UpdateKeys(newNode, config.Netclient(), client); err != nil {
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
	config.UpdateNodeMap(network, *newNode)
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, newNode.Network, "error updating node configuration: ", err.Error())
	}
	//nameserver := server.CoreDNSAddr
	//file := config.GetNetclientInterfacePath() + config.Netclient.Interface + ".conf"

	nc := wireguard.NewNCIface(config.Netclient().MTU)
	//if newNode.ListenPort != newNode.LocalListenPort {
	//	if err := nc.Close(); err != nil {
	//		logger.Log(0, "error remove interface", newNode.Interface, err.Error())
	//	}
	//	err = config.ModPort(&config.Netclient)
	//	if err != nil {
	//		logger.Log(0, "network:", newNode.Network, "error modifying node port on", config.Netclient.Name, "-", err.Error())
	//
	//	return
	//	}
	//	ifaceDelta = true
	//	informPortChange(newNode)
	//}
	if err := wireguard.UpdateWgInterface(newNode, config.Netclient()); err != nil {

		logger.Log(0, "error updating wireguard config "+err.Error())
		return
	}
	if keepaliveChange {
		wireguard.UpdateKeepAlive(newNode.PersistentKeepalive)
	}
	logger.Log(0, "applying WG conf ")
	if err = nc.Create(); err != nil {
		logger.Log(0, "failed to create WG iface after update")
	}
	// wireguard.ApplyConf(newNode, file)
	time.Sleep(time.Second)

	if ifaceDelta { // if a change caused an ifacedelta we need to notify the server to update the peers
		doneErr := publishSignal(newNode, DONE)
		if doneErr != nil {
			logger.Log(0, "network:", newNode.Network, "could not notify server to update peers after interface change")
		} else {
			logger.Log(0, "network:", newNode.Network, "signalled finished interface update to server")
		}
	} else if hubChange {
		doneErr := publishSignal(newNode, DONE)
		if doneErr != nil {
			logger.Log(0, "network:", newNode.Network, "could not notify server to update peers after hub change")
		} else {
			logger.Log(0, "network:", newNode.Network, "signalled finished hub update to server")
		}
	}
	//deal with DNS
	if newNode.DNSOn && shouldDNSChange && config.Netclient().Interface != "" {
		logger.Log(0, "network:", newNode.Network, "settng DNS off")
		if err := removeHostDNS(config.Netclient().Interface, ncutils.IsWindows()); err != nil {
			logger.Log(0, "network:", newNode.Network, "error removing netmaker profile from /etc/hosts "+err.Error())
		}
		//		_, err := ncutils.RunCmd("/usr/bin/resolvectl revert "+nodeCfg.Node.Interface, true)
		//		if err != nil {
		//			logger.Log(0, "error applying dns" + err.Error())
		//		}
	}
	_ = UpdateLocalListenPort(newNode)
}

// UpdatePeers -- mqtt message handler for peers/<Network>/<NodeID> topic
func UpdatePeers(client mqtt.Client, msg mqtt.Message) {
	var peerUpdate models.PeerUpdate
	var err error
	network := parseNetworkFromTopic(msg.Topic())
	node := config.GetNode(network)
	server := config.GetServer(node.Server)
	logger.Log(3, "received peer update for", network)
	data, err := decryptMsg(&node, msg.Payload())
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(data), &peerUpdate)
	if err != nil {
		logger.Log(0, "error unmarshalling peer data")
		return
	}
	// see if cached hit, if so skip
	var currentMessage = read(peerUpdate.Network, lastPeerUpdate)
	if currentMessage == string(data) {
		return
	}
	insert(peerUpdate.Network, lastPeerUpdate, string(data))
	// check version
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
	//check if internet gateway has changed
	oldGateway := node.InternetGateway
	if (internetGateway == nil && oldGateway != nil) || (internetGateway != nil && internetGateway.String() != oldGateway.String()) {
		node.InternetGateway = internetGateway
		config.UpdateNodeMap(node.Network, node)
		if err := config.WriteNodeConfig(); err != nil {
			logger.Log(0, "failed to save internet gateway", err.Error())
		}
	}
	//nc := wireguard.NewNCIface(&config.Netclient)
	//nc.Create()
	wireguard.SetPeers()
	logger.Log(0, "network:", node.Network, "received peer update for node "+node.ID+" "+node.Network)
	if node.DNSOn {
		if err := setHostDNS(peerUpdate.DNS, config.Netclient().Interface, ncutils.IsWindows()); err != nil {
			logger.Log(0, "network:", node.Network, "error updating /etc/hosts "+err.Error())
			return
		}
	} else {
		if err := removeHostDNS(config.Netclient().Interface, ncutils.IsWindows()); err != nil {
			logger.Log(0, "network:", node.Network, "error removing profile from /etc/hosts "+err.Error())
			return
		}
	}
	UpdateLocalListenPort(&node)
}

func setHostDNS(dns, iface string, windows bool) error {
	etchosts := "/etc/hosts"
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if windows {
		etchosts = "c:\\windows\\system32\\drivers\\etc\\hosts"
		lockfile = temp + "\\netclient-lock"
	}
	if _, err := os.Stat(lockfile); !errors.Is(err, os.ErrNotExist) {
		return errors.New("/etc/hosts file is locked .... aborting")
	}
	lock, err := os.Create(lockfile)
	if err != nil {
		return fmt.Errorf("could not create lock file %w", err)
	}
	lock.Close()
	defer os.Remove(lockfile)
	dnsdata := strings.NewReader(dns)
	profile, err := parser.ParseProfile(dnsdata)
	if err != nil {
		return err
	}
	hosts, err := file.NewFile(etchosts)
	if err != nil {
		return err
	}
	profile.Name = strings.ToLower(iface)
	profile.Status = types.Enabled
	if err := hosts.ReplaceProfile(profile); err != nil {
		return err
	}
	if err := hosts.Flush(); err != nil {
		return err
	}
	return nil
}

func parseNetworkFromTopic(topic string) string {
	return strings.Split(topic, "/")[1]
}
