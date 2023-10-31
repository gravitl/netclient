package functions

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/firewall"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/nmproxy/turn"
	"github.com/gravitl/netclient/routes"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/txeh"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MQTimeout - time out for mqtt connections
const MQTimeout = 30

// All -- mqtt message hander for all ('#') topics
var All mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	slog.Info("default message handler -- received message but not handling", "topic", msg.Topic())
}

// NodeUpdate -- mqtt message handler for /update/<NodeID> topic
func NodeUpdate(client mqtt.Client, msg mqtt.Message) {
	network := parseNetworkFromTopic(msg.Topic())
	slog.Info("processing node update for network", "network", network)
	node := config.GetNode(network)
	server := config.Servers[node.Server]
	data, err := decryptMsg(server.Name, msg.Payload())
	if err != nil {
		slog.Error("error decrypting message", "error", err)
		return
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
	time.Sleep(time.Second)
	if ifaceDelta { // if a change caused an ifacedelta we need to notify the server to update the peers
		doneErr := publishSignal(&newNode, DONE)
		if doneErr != nil {
			slog.Warn("could not notify server to update peers after interface change", "network:", newNode.Network, "error", doneErr)
		} else {
			slog.Info("signalled finished interface update to server", "network", newNode.Network)
		}
	}
}

// HostPeerUpdate - mq handler for host peer update peers/host/<HOSTID>/<SERVERNAME>
func HostPeerUpdate(client mqtt.Client, msg mqtt.Message) {
	var peerUpdate models.HostPeerUpdate
	var err error
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
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		slog.Error("error decrypting message", "error", err)
		return
	}
	err = json.Unmarshal([]byte(data), &peerUpdate)
	if err != nil {
		slog.Error("error unmarshalling peer data", "error", err)
		return
	}
	if server.UseTurn {
		turn.ResetCh <- struct{}{}
	}
	if peerUpdate.ServerVersion != config.Version {
		slog.Warn("server/client version mismatch", "server", peerUpdate.ServerVersion, "client", config.Version)
		vlt, err := versionLessThan(config.Version, peerUpdate.ServerVersion)
		if err != nil {
			slog.Error("error checking version less than", "error", err)
			return
		}
		if vlt && config.Netclient().Host.AutoUpdate {
			slog.Info("updating client to server's version", "version", peerUpdate.ServerVersion)
			if err := UseVersion(peerUpdate.ServerVersion, false); err != nil {
				slog.Error("error updating client to server's version", "error", err)
			} else {
				slog.Info("updated client to server's version", "version", peerUpdate.ServerVersion)
				daemon.HardRestart()
			}
			//daemon.Restart()
		}
	}
	if peerUpdate.ServerVersion != server.Version {
		slog.Info("updating server version", "server", serverName, "version", peerUpdate.ServerVersion)
		server.Version = peerUpdate.ServerVersion
		config.WriteServerConfig()
	}
	gwDetected := config.GW4PeerDetected || config.GW6PeerDetected
	currentGW4 := config.GW4Addr
	currentGW6 := config.GW6Addr
	isInetGW := config.UpdateHostPeers(peerUpdate.Peers)
	_ = config.WriteNetclientConfig()
	_ = wireguard.SetPeers(false)
	if len(peerUpdate.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(peerUpdate.EgressRoutes)
	}
	if err = routes.SetNetmakerPeerEndpointRoutes(config.Netclient().DefaultInterface); err != nil {
		slog.Warn("error when setting peer routes after peer update", "error", err)
	}
	gwDelta := (currentGW4.IP != nil && !currentGW4.IP.Equal(config.GW4Addr.IP)) ||
		(currentGW6.IP != nil && !currentGW6.IP.Equal(config.GW6Addr.IP))
	originalGW := currentGW4
	if originalGW.IP != nil {
		originalGW = currentGW6
	}
	handlePeerInetGateways(
		gwDetected,
		isInetGW,
		gwDelta,
		&originalGW,
	)
	go handleEndpointDetection(peerUpdate.Peers, peerUpdate.HostNetworkInfo)
	handleFwUpdate(serverName, &peerUpdate.FwUpdate)
}

// HostUpdate - mq handler for host update host/update/<HOSTID>/<SERVERNAME>
func HostUpdate(client mqtt.Client, msg mqtt.Message) {
	var hostUpdate models.HostUpdate
	var err error
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		slog.Error("error decrypting message", "error", err)
		return
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
		if err := UseVersion(sv, false); err != nil {
			slog.Error("error upgrading client to server's version", "error", err)
			break
		}
		slog.Info("upgraded client to server's version, restarting", "version", sv)
		if err := daemon.HardRestart(); err != nil {
			slog.Error("failed to hard restart daemon", "error", err)
		}
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
		slog.Info("added node to network", "network", hostUpdate.Node.Network, "server", serverName)
		clearRetainedMsg(client, msg.Topic()) // clear message before ACK
		if err = PublishHostUpdate(serverName, models.Acknowledgement); err != nil {
			slog.Error("failed to response with ACK to server", "server", serverName, "error", err)
		}
		setSubscriptions(client, &nodeCfg)
		resetInterface = true
	case models.DeleteHost:
		clearRetainedMsg(client, msg.Topic())
		unsubscribeHost(client, serverName)
		deleteHostCfg(client, serverName)
		config.WriteNodeConfig()
		config.WriteServerConfig()
		restartDaemon = true
	case models.UpdateHost:
		resetInterface, restartDaemon, sendHostUpdate = config.UpdateHost(&hostUpdate.Host)
		if sendHostUpdate {
			if err := PublishHostUpdate(config.CurrServer, models.UpdateHost); err != nil {
				slog.Error("could not publish host update", err.Error())
			}
		}
		clearMsg = true
	case models.RequestAck:
		clearRetainedMsg(client, msg.Topic()) // clear message before ACK
		if err = PublishHostUpdate(serverName, models.Acknowledgement); err != nil {
			slog.Error("failed to response with ACK to server", "server", serverName, "error", err)
		}
	case models.SignalHost:
		turn.PeerSignalCh <- hostUpdate.Signal
	case models.UpdateKeys:
		clearRetainedMsg(client, msg.Topic()) // clear message
		UpdateKeys()
	case models.RequestPull:
		clearRetainedMsg(client, msg.Topic())
		Pull(true)
	default:
		slog.Error("unknown host action", "action", hostUpdate.Action)
		return
	}
	if err = config.WriteNetclientConfig(); err != nil {
		slog.Error("failed to write host config", "error", err)
		return
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
		nc := wireguard.GetInterface()
		nc.Close()
		nc = wireguard.NewNCIface(config.Netclient(), config.GetNodes())
		nc.Create()
		if err := nc.Configure(); err != nil {
			slog.Error("could not configure netmaker interface", "error", err)
			return
		}

		if err = wireguard.SetPeers(false); err == nil {
			if err = routes.SetNetmakerPeerEndpointRoutes(config.Netclient().DefaultInterface); err != nil {
				slog.Error("error when setting peer routes after host update", "error", err)
			}
		}
	}
}

// handleEndpointDetection - select best interface for each peer and set it as endpoint
func handleEndpointDetection(peers []wgtypes.PeerConfig, peerInfo models.HostInfoMap) {
	currentCidrs := getAllAllowedIPs(peers[:])
	for idx := range peers {

		peerPubKey := peers[idx].PublicKey.String()
		if peerInfo, ok := peerInfo[peerPubKey]; ok {
			if peerInfo.IsStatic {
				// peer is a static host shouldn't disturb the configuration set by the user
				continue
			}
			for i := range peerInfo.Interfaces {
				peerIface := peerInfo.Interfaces[i]
				peerIP := peerIface.Address.IP
				if peers[idx].Endpoint == nil || peerIP == nil {
					continue
				}
				// check to skip bridge network
				if ncutils.IsBridgeNetwork(peerIface.Name) {
					continue
				}
				if strings.Contains(peerIP.String(), "127.0.0.") ||
					peerIP.IsMulticast() ||
					(peerIP.IsLinkLocalUnicast() && strings.Count(peerIP.String(), ":") >= 2) ||
					peers[idx].Endpoint.IP.Equal(peerIP) ||
					isAddressInPeers(peerIP, currentCidrs) {
					continue
				}
				if peerIP.IsPrivate() {
					networking.FindBestEndpoint(
						peerIP.String(),
						peerPubKey,
						peerInfo.ListenPort,
					)
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

// dnsUpdate - mq handler for host update dns/<HOSTID>/server
func dnsUpdate(client mqtt.Client, msg mqtt.Message) {
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if err := config.Lock(lockfile); err != nil {
		slog.Error("could not create lock file", "error", err)
		return
	}
	defer config.Unlock(lockfile)
	var dns models.DNSUpdate
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	if err := json.Unmarshal([]byte(data), &dns); err != nil {
		slog.Error("error unmarshalling dns update", "error", err)
	}
	if config.Netclient().Debug {
		log.Println("dnsUpdate received", dns)
	}
	var currentMessage = read("dns", lastDNSUpdate)
	if currentMessage == string(data) {
		slog.Info("cache hit on dns update ... skipping")
		return
	}
	insert("dns", lastDNSUpdate, string(data))
	slog.Info("received dns update", "name", dns.Name, "address", dns.Address, "action", dns.Action)
	applyDNSUpdate(dns)
}

func applyDNSUpdate(dns models.DNSUpdate) {
	if config.Netclient().Debug {
		log.Println(dns)
	}
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		slog.Error("failed to read hosts file", "error", err)
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
		ok, ip, _ := hosts.HostAddressLookup(dns.Name, txeh.IPFamilyV4, etcHostsComment)
		if !ok {
			slog.Error("failed to find dns address for host", "host", dns.Name)
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
		slog.Error("error saving hosts file", "error", err)
		return
	}
}

// dnsAll- mq handler for host update dnsall/<HOSTID>/server
func dnsAll(client mqtt.Client, msg mqtt.Message) {
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if err := config.Lock(lockfile); err != nil {
		slog.Error("could not create lock file", "error", err)
		return
	}
	defer config.Unlock(lockfile)
	var dns []models.DNSUpdate
	serverName := parseServerFromTopic(msg.Topic())
	server := config.GetServer(serverName)
	if server == nil {
		slog.Error("server not found in config", "server", serverName)
		return
	}
	data, err := decryptMsg(serverName, msg.Payload())
	if err != nil {
		return
	}
	if err := json.Unmarshal([]byte(data), &dns); err != nil {
		slog.Error("error unmarshalling dns update", "error", err)
	}
	if config.Netclient().Debug {
		log.Println("all dns", dns)
	}
	var currentMessage = read("dnsall", lastALLDNSUpdate)
	slog.Info("received initial dns", "dns", dns)
	if currentMessage == string(data) {
		slog.Info("cache hit on all dns ... skipping")
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
		slog.Error("failed to read hosts file", "error", err)
		return
	}
	for _, entry := range dns {
		if entry.Action != models.DNSInsert {
			slog.Info("invalid dns actions", "action", entry.Action)
			continue
		}
		hosts.AddHost(entry.Address, entry.Name, etcHostsComment)
	}

	if err := hosts.Save(); err != nil {
		slog.Error("error saving hosts file", "error", err)
		return
	}
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

func handlePeerInetGateways(gwDetected, isHostInetGateway, gwDelta bool, originalGW *net.IPNet) { // isHostInetGateway indicates if host should worry about setting gateways
	if gwDelta { // handle switching gateway IP to other GW peer
		if config.GW4PeerDetected {
			if err := routes.RemoveDefaultGW(originalGW); err != nil {
				slog.Error("failed to remove default gateway from peer", "gateway", originalGW, "error", err)
			}
			if err := routes.SetDefaultGateway(&config.GW4Addr); err != nil {
				slog.Error("failed to set default gateway to peer", "gateway", config.GW4Addr, "error", err)
			}
		} else if config.GW6PeerDetected {
			if err := routes.SetDefaultGateway(&config.GW6Addr); err != nil {
				slog.Error("failed to set default gateway to peer", "gateway", config.GW6Addr, "error", err)
			}
		}
	} else {
		if !gwDetected && config.GW4PeerDetected && !isHostInetGateway { // ipv4 gateways take priority
			if err := routes.SetDefaultGateway(&config.GW4Addr); err != nil {
				slog.Error("failed to set default gateway to peer", "gateway", config.GW4Addr, "error", err)
			}
		} else if gwDetected && !config.GW4PeerDetected {
			if err := routes.RemoveDefaultGW(&config.GW4Addr); err != nil {
				slog.Error("failed to remove default gateway to peer", "gateway", config.GW4Addr, "error", err)
			}
		} else if !gwDetected && config.GW6PeerDetected && !isHostInetGateway {
			if err := routes.SetDefaultGateway(&config.GW6Addr); err != nil {
				slog.Error("failed to set default gateway to peer", "gateway", config.GW6Addr, "error", err)
			}
		} else if gwDetected && !config.GW6PeerDetected {
			if err := routes.RemoveDefaultGW(&config.GW6Addr); err != nil {
				slog.Error("failed to remove default gateway to peer", "gateway", config.GW6Addr, "error", err)
			}
		}
	}
}

func handleFwUpdate(server string, payload *models.FwUpdate) {

	if payload.IsEgressGw {
		firewall.SetEgressRoutes(server, payload.EgressInfo)
	} else {
		firewall.DeleteEgressGwRoutes(server)
	}

}
