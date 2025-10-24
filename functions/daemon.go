package functions

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	externalip "github.com/glendc/go-external-ip"
	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/firewall"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/stun"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	lastNodeUpdate   = "lnu"
	lastDNSUpdate    = "ldu"
	lastALLDNSUpdate = "ladu"
	// MQ_TIMEOUT - timeout for MQ
	MQ_TIMEOUT = 30
)

var (
	Mqclient     mqtt.Client
	messageCache = new(sync.Map)
)

type cachedMessage struct {
	Message  string
	LastSeen time.Time
}

// Daemon runs netclient daemon
func Daemon() {
	slog.Info("starting netclient daemon", "version", config.Version)
	daemon.RemoveAllLockFiles()
	if err := ncutils.SavePID(); err != nil {
		slog.Error("unable to save PID on daemon startup", "error", err)
		os.Exit(1)
	}
	if err := local.SetIPForwarding(); err != nil {
		slog.Warn("unable to set IPForwarding", "error", err)
	}
	wg := sync.WaitGroup{}
	quit := make(chan os.Signal, 1)
	reset := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, os.Interrupt)
	signal.Notify(reset, syscall.SIGHUP)

	cancel := startGoRoutines(&wg)

	for {
		select {
		case <-quit:
			slog.Info("shutting down netclient daemon")
			dns.GetDNSServerInstance().Stop()
			//check if it needs to restore the default gateway
			checkAndRestoreDefaultGateway()
			closeRoutines([]context.CancelFunc{
				cancel,
			}, &wg)
			config.FwClose()
			slog.Info("shutdown complete")
			return
		case <-reset:
			slog.Info("received reset")
			dns.GetDNSServerInstance().Stop()
			config.FwClose()
			//check if it needs to restore the default gateway
			checkAndRestoreDefaultGateway()
			closeRoutines([]context.CancelFunc{
				cancel,
			}, &wg)
			slog.Info("resetting daemon")
			cancel = startGoRoutines(&wg)
		}
	}
}

// checkAndRestoreDefaultGateway -check if it needs to restore the default gateway
func checkAndRestoreDefaultGateway() {
	if config.Netclient().CurrGwNmIP == nil {
		return
	}
	//get the current default gateway
	ip, err := wireguard.GetDefaultGatewayIp()
	if err != nil {
		slog.Error("error loading current default gateway", "error", err.Error())
		return
	}
	//restore the default gateway when the current default gateway is not the same as the one in config
	if !config.Netclient().OriginalDefaultGatewayIp.Equal(ip) {
		err = wireguard.RestoreInternetGw()
		if err != nil {
			slog.Error("error restoring default gateway", "error", err.Error())
			return
		}
	}
}

func closeRoutines(closers []context.CancelFunc, wg *sync.WaitGroup) {
	for i := range closers {
		closers[i]()
	}
	if Mqclient != nil {
		Mqclient.Disconnect(250)
	}
	wg.Wait()
	// clear cache
	cache.EndpointCache = sync.Map{}
	cache.SkipEndpointCache = sync.Map{}
	cache.EgressRouteCache = sync.Map{}
	signalThrottleCache = sync.Map{}
	slog.Info("closing netmaker interface")
	iface := wireguard.GetInterface()
	iface.Close()
}

// startGoRoutines starts the daemon goroutines
func startGoRoutines(wg *sync.WaitGroup) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := config.ReadNetclientConfig(); err != nil {
		slog.Warn("error reading netclient config file", "error", err)
	}

	config.UpdateNetclient(*config.Netclient())
	ncutils.SetInterfaceName(config.Netclient().Interface)
	if err := config.ReadServerConf(); err != nil {
		slog.Warn("error reading server map from disk", "error", err)
	}
	// initialize firewall manager
	var err error
	config.FwClose, err = firewall.Init()
	if err != nil {
		slog.Info("failed to intialize firewall: ", "error", err.Error())
	}
	updateConfig := false

	config.SetServerCtx()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		server.StunServers = ""
	}

	if server.Stun && server.StunServers != "" {
		stun.LoadStunServers(server.StunServers)
	} else {
		stun.SetDefaultStunServers()
	}
	netclientCfg := config.Netclient()
	if netclientCfg.Host.OS == "linux" || netclientCfg.Host.OS == "windows" {
		dns.InitDNSConfig()
		updateConfig = true
	}

	if !netclientCfg.IsStaticPort {
		if freeport, err := ncutils.GetFreePort(ncutils.NetclientDefaultPort, netclientCfg.ListenPort, false); err != nil {
			slog.Warn("no free ports available for use by netclient", "error", err.Error())
		} else if freeport != netclientCfg.ListenPort {
			slog.Info("port has changed", "old port", netclientCfg.ListenPort, "new port", freeport)
			netclientCfg.ListenPort = freeport
			updateConfig = true
		}

		if netclientCfg.WgPublicListenPort == 0 {
			netclientCfg.WgPublicListenPort = config.WgPublicListenPort
			updateConfig = true
		}

	} else {
		netclientCfg.WgPublicListenPort = netclientCfg.ListenPort
		updateConfig = true
	}

	if !netclientCfg.IsStatic {
		// IPV4
		config.HostPublicIP, config.WgPublicListenPort, config.HostNatType = holePunchWgPort(4, netclientCfg.ListenPort)
		slog.Info("wireguard public listen port: ", "port", config.WgPublicListenPort)
		if config.HostPublicIP != nil && !config.HostPublicIP.IsUnspecified() {
			netclientCfg.EndpointIP = config.HostPublicIP
			updateConfig = true
		} else {
			slog.Warn("GetPublicIPv4 error:", "Warn", "no ipv4 found")
			netclientCfg.EndpointIP = nil
			updateConfig = true
		}
		if netclientCfg.NatType == "" {
			netclientCfg.NatType = config.HostNatType
			updateConfig = true
		}
		// IPV6
		publicIP6, wgport, natType := holePunchWgPort(6, netclientCfg.ListenPort)
		if publicIP6 != nil && !publicIP6.IsUnspecified() {
			netclientCfg.EndpointIPv6 = publicIP6
			config.HostPublicIP6 = publicIP6
			if config.HostPublicIP == nil {
				config.WgPublicListenPort = wgport
				config.HostNatType = natType
			}
			updateConfig = true
		} else {
			slog.Warn("GetPublicIPv6 Warn: ", "Warn", "no ipv6 found")
			netclientCfg.EndpointIPv6 = nil
			updateConfig = true
		}

	}

	originalDefaultGwIP, err := wireguard.GetDefaultGatewayIp()
	if err == nil && originalDefaultGwIP != nil && (netclientCfg.CurrGwNmIP == nil || !netclientCfg.CurrGwNmIP.Equal(originalDefaultGwIP)) {
		netclientCfg.OriginalDefaultGatewayIp = originalDefaultGwIP
		updateConfig = true
	}

	if updateConfig {
		config.UpdateNetclient(*netclientCfg)
		if err := config.WriteNetclientConfig(); err != nil {
			slog.Warn("error writing endpoint/port netclient config file", "error", err)
		}
	}
	slog.Info("configuring netmaker wireguard interface")
	pullresp, _, _, pullErr := Pull(false, true)
	if pullErr != nil {
		slog.Error("fail to pull config from server", "error", pullErr.Error())
	}
	nc := wireguard.NewNCIface(netclientCfg, config.GetNodes())
	if err := nc.Create(); err != nil {
		slog.Error("error creating netclient interface", "error", err)
	}
	if err := nc.Configure(); err != nil {
		slog.Error("error configuring netclient interface", "error", err)
	}
	wireguard.SetPeers(true)
	if len(pullresp.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pullresp.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pullresp.EgressRoutes)
	} else {
		wireguard.RemoveEgressRoutes()
	}
	if pullErr == nil && pullresp.EndpointDetection {
		go handleEndpointDetection(pullresp.Peers, pullresp.HostNetworkInfo)
	} else {
		cache.EndpointCache = sync.Map{}
		cache.SkipEndpointCache = sync.Map{}
	}
	server = config.GetServer(config.CurrServer)
	if server == nil {
		return cancel
	}
	logger.Log(1, "started daemon for server ", server.Name)
	// set original default gw info

	// check if default gw needs to be set
	if pullErr == nil {
		gwIP, err := wireguard.GetDefaultGatewayIp()
		if err == nil {
			if pullresp.ChangeDefaultGw && !pullresp.DefaultGwIp.Equal(gwIP) {
				if !wireguard.GetIGWMonitor().IsCurrentIGW(gwIP) {
					var igw wgtypes.PeerConfig
					for _, peer := range pullresp.Peers {
						for _, peerIP := range peer.AllowedIPs {
							if peerIP.String() == wireguard.IPv4Network || peerIP.String() == wireguard.IPv6Network {
								igw = peer
								break
							}
						}
					}

					// unlikely that the gwIP is netmaker IP, but still
					// reset the igw.
					_ = wireguard.RestoreInternetGw()

					err = wireguard.SetInternetGw(igw.PublicKey.String(), pullresp.DefaultGwIp)
					if err != nil {
						slog.Warn("failed to set inet gw", "error", err)
					}
				}
			}
		}
	}

	wg.Add(1)
	go messageQueue(ctx, wg, server)
	wg.Add(1)
	go Checkin(ctx, wg)
	networking.InitialiseIfaceMetricsServer(ctx, wg)
	if server.IsPro {
		wg.Add(1)
		go watchPeerConnections(ctx, wg)
		wg.Add(1)
		go wireguard.StartEgressHAFailOverThread(ctx, wg)
	} else {
		wg.Add(1)
		go checkPeerEndpoints(ctx, wg)
	}
	wg.Add(1)
	go mqFallback(ctx, wg)

	if server.ManageDNS {
		if dns.GetDNSServerInstance().AddrStr == "" {
			dns.GetDNSServerInstance().Start()
		}
	} else {
		dns.GetDNSServerInstance().Stop()
	}
	go func() {
		time.Sleep(time.Second * 45)
		callPublishMetrics(true)
	}()

	return cancel
}

// sets up Message Queue and subsribes/publishes updates to/from server
// the client should subscribe to ALL nodes that exist on server locally
func messageQueue(ctx context.Context, wg *sync.WaitGroup, server *config.Server) {
	defer wg.Done()
	slog.Info("netclient message queue started for server:", "server", server.Name)
	err := setupMQTT(server)
	if err != nil {
		slog.Error("unable to connect to broker", "server", server.Broker, "error", err)
		return
	}
	defer func() {
		if Mqclient != nil {
			Mqclient.Disconnect(250)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down message queue", "server", server.Name)
}

// setupMQTT creates a connection to broker
func setupMQTT(server *config.Server) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(server.Broker)
	if server.BrokerType == "emqx" {
		opts.SetUsername(config.Netclient().ID.String())
		opts.SetPassword(config.Netclient().HostPass)
	} else {
		opts.SetUsername(server.MQUserName)
		opts.SetPassword(server.MQPassword)
	}
	opts.SetClientID(logic.RandomString(23))
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second << 2)
	opts.SetKeepAlive(time.Second * 15)
	opts.SetWriteTimeout(time.Minute)
	opts.SetCleanSession(true)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		slog.Info("mqtt connect handler")
		nodes := config.GetNodes()
		for _, node := range nodes {
			node := node
			setSubscriptions(client, &node)
			setDNSSubscriptions(client, &node)
		}
		setHostSubscription(client, server.Name)
		time.Sleep(time.Second * 3)
		checkin()
	})
	opts.SetOrderMatters(false)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		slog.Warn("detected broker connection lost for", "server", server.Broker)
	})
	Mqclient = mqtt.NewClient(opts)
	var connecterr error
	for count := 0; count < 3; count++ {
		connecterr = nil
		if token := Mqclient.Connect(); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
			logger.Log(0, "unable to connect to broker, retrying ...")
			if token.Error() == nil {
				connecterr = errors.New("connect timeout")
			} else {
				connecterr = token.Error()
			}
		}
	}
	if connecterr != nil {
		slog.Error("unable to connect to broker", "server", server.Broker, "error", connecterr)
		return connecterr
	}
	if err := PublishHostUpdate(server.Name, models.Acknowledgement); err != nil {
		slog.Error("failed to send initial ACK to server", "server", server.Name, "error", err)
	} else {
		slog.Info("successfully requested ACK on server", "server", server.Name)
	}
	return nil
}

// func setMQTTSingenton creates a connection to broker for single use (ie to publish a message)
// only to be called from cli (eg. connect/disconnect, join, leave) and not from daemon ---
func setupMQTTSingleton(server *config.Server, publishOnly bool) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(server.Broker)
	if server.BrokerType == "emqx" {
		opts.SetUsername(config.Netclient().ID.String())
		opts.SetPassword(config.Netclient().HostPass)
	} else {
		opts.SetUsername(server.MQUserName)
		opts.SetPassword(server.MQPassword)
	}
	opts.SetClientID(logic.RandomString(9))
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second * 4)
	opts.SetKeepAlive(time.Second * 30)
	opts.SetWriteTimeout(time.Minute)
	opts.SetCleanSession(true)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		if !publishOnly {
			slog.Info("mqtt connect handler")
			nodes := config.GetNodes()
			for _, node := range nodes {
				node := node
				setSubscriptions(client, &node)
				setDNSSubscriptions(client, &node)
			}
			setHostSubscription(client, server.Name)
		}
		slog.Info("successfully connected to", "server", server.Broker)
	})
	opts.SetOrderMatters(true)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		slog.Warn("detected broker connection lost for", "server", server.Broker)
	})
	Mqclient = mqtt.NewClient(opts)

	var connecterr error
	if token := Mqclient.Connect(); !token.WaitTimeout(5*time.Second) || token.Error() != nil {
		if token.Error() == nil {
			connecterr = errors.New("connect timeout")
		} else {
			connecterr = token.Error()
		}
		slog.Error("unable to connect to broker", "server", server.Broker, "error", connecterr)
	}
	return connecterr
}

// setHostSubscription sets MQ client subscriptions for host
// should be called for each server host is registered on.
func setHostSubscription(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	slog.Info("subscribing to host updates for", "host", hostID, "server", server)
	clearRetainedMsg(client, fmt.Sprintf("peers/host/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostPeerUpdate)); token.Wait() && token.Error() != nil {
		slog.Error("unable to subscribe to host peer updates", "host", hostID, "server", server, "error", token.Error())
		return
	}
	clearRetainedMsg(client, fmt.Sprintf("host/update/%s/%s", hostID.String(), server))
	slog.Info("subscribing to host updates for", "host", hostID, "server", server)
	if token := client.Subscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostUpdate)); token.Wait() && token.Error() != nil {
		slog.Error("unable to subscribe to host updates", "host", hostID, "server", server, "error", token.Error())
		return
	}

}

// setSubcriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setSubscriptions(client mqtt.Client, node *config.Node) {
	clearRetainedMsg(client, fmt.Sprintf("node/update/%s/%s", node.Network, node.ID))
	if token := client.Subscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID), 0, mqtt.MessageHandler(NodeUpdate)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to subscribe to updates for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to subscribe to updates for node ", "node", node.ID, "error", token.Error())
		}
		return
	}
	slog.Info("subscribed to updates for node", "node", node.ID, "network", node.Network)
}

// setDNSSubscriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setDNSSubscriptions(client mqtt.Client, node *config.Node) {
	if token := client.Subscribe(fmt.Sprintf("host/dns/sync/%s", node.Network), 0, mqtt.MessageHandler(DNSSync)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to subscribe to DNS sync for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to subscribe to DNS sync for node ", "node", node.ID, "error", token.Error())
		}
		return
	}
	slog.Info("subscribed to DNS sync for node", "node", node.ID, "network", node.Network)
}

func unzipPayload(data []byte) (resData []byte, err error) {
	b := bytes.NewBuffer(data)

	var r io.Reader
	r, err = gzip.NewReader(b)
	if err != nil {
		return
	}

	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return
	}

	resData = resB.Bytes()

	return
}

func decryptMsg(serverName string, msg []byte) ([]byte, error) {
	if len(msg) <= 24 { // make sure message is of appropriate length
		return nil, fmt.Errorf("received invalid message from broker %v", msg)
	}
	host := config.Netclient()
	// setup the keys
	diskKey, err := ncutils.ConvertBytesToKey(host.TrafficKeyPrivate)
	if err != nil {
		return nil, err
	}

	server := config.GetServer(serverName)
	if server == nil {
		return nil, errors.New("nil server for " + serverName)
	}
	serverPubKey, err := ncutils.ConvertBytesToKey(server.TrafficKey)
	if err != nil {
		return nil, err
	}
	return DeChunk(msg, serverPubKey, diskKey)
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	// Create AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM (Galois/Counter Mode) cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Separate nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func read(network, which string) string {
	val, isok := messageCache.Load(fmt.Sprintf("%s%s", network, which))
	if isok {
		var readMessage = val.(cachedMessage) // fetch current cached message
		if readMessage.LastSeen.IsZero() {
			return ""
		}
		if time.Now().After(readMessage.LastSeen.Add(time.Hour * 24)) { // check if message has been there over a minute
			messageCache.Delete(fmt.Sprintf("%s%s", network, which)) // remove old message if expired
			return ""
		}
		return readMessage.Message // return current message if not expired
	}
	return ""
}

func insert(network, which, cache string) {
	var newMessage = cachedMessage{
		Message:  cache,
		LastSeen: time.Now(),
	}
	messageCache.Store(fmt.Sprintf("%s%s", network, which), newMessage)
}

// on a delete usually, pass in the nodecfg to unsubscribe client broker communications
// for the node in nodeCfg
func unsubscribeNode(client mqtt.Client, node *config.Node) {
	var ok = true
	if token := client.Unsubscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to unsubscribe from updates for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to unsubscribe from updates for node ", "node", node.ID, "error", token.Error())
		}
		ok = false
	} // peer updates belong to host now

	if token := client.Unsubscribe(fmt.Sprintf("host/dns/sync/%s", node.Network)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to unsubscribe from DNS sync for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to unsubscribe from DNS sync for node ", "node", node.ID, "error", token.Error())
		}
		ok = false
	}

	if ok {
		slog.Info("unsubscribed from updates for node", "node", node.ID, "network", node.Network)
	}
}

// unsubscribe client broker communications for host topics
func unsubscribeHost(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	slog.Info("removing subscription for host peer updates", "host", hostID, "server", server)
	if token := client.Unsubscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		slog.Error("unable to unsubscribe from host peer updates", "host", hostID, "server", server, "error", token.Error())
		return
	}
	slog.Info("removing subscription for host updates", "host", hostID, "server", server)
	if token := client.Unsubscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		slog.Error("unable to unsubscribe from host updates", "host", hostID, "server", server, "error", token.Error)
		return
	}
}

// UpdateKeys -- updates private key and returns new publickey
func UpdateKeys() error {
	var err error
	slog.Info("received message to update wireguard keys")
	host := config.Netclient()
	host.PrivateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		slog.Error("error generating privatekey ", "error", err)
		return err
	}
	host.PublicKey = host.PrivateKey.PublicKey()
	if err := config.WriteNetclientConfig(); err != nil {
		slog.Error("error saving netclient config:", "error", err)
	}
	PublishHostUpdate(config.CurrServer, models.UpdateHost)
	daemon.Restart()
	return nil
}

func holePunchWgPort(proto, portToStun int) (pubIP net.IP, pubPort int, natType string) {
	defer func() {
		//ncutils.TraceCaller()
		slog.Debug("holePunchWgPort", "proto", proto, "PortToStun", portToStun, "PubIP", pubIP.String(), "PubPort", pubPort, "NatType", natType)
	}()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		stun.SetDefaultStunServers()
	}
	_, ipErr := GetPublicIP(uint(proto))
	if ipErr != nil {
		return
	}
	if server.Stun {
		pubIP, pubPort, natType = stun.HolePunch(portToStun, proto)
	} else {
		pubIP, _ = GetPublicIP(uint(proto))
		pubPort = config.Netclient().ListenPort
		natType = "public"
	}
	if pubIP == nil || pubIP.IsUnspecified() { // if stun has failed fallback to ip service to get publicIP
		publicIP, err := GetPublicIP(uint(proto))
		if err != nil {
			slog.Warn("failed to get publicIP", "error", err)
			return
		}
		pubIP = publicIP
		pubPort = portToStun
	}
	return
}

func GetPublicIP(proto uint) (net.IP, error) {
	// Create the default consensus,
	// using the default configuration and no logger.
	consensus := externalip.NewConsensus(&externalip.ConsensusConfig{
		Timeout: time.Second * 10,
	}, nil)
	consensus.AddVoter(externalip.NewHTTPSource("https://icanhazip.com/"), 3)
	consensus.AddVoter(externalip.NewHTTPSource("https://ifconfig.me/ip"), 3)
	consensus.AddVoter(externalip.NewHTTPSource("https://myexternalip.com/raw"), 3)
	// By default Ipv4 or Ipv6 is returned,
	// use the function below to limit yourself to IPv4,
	// or pass in `6` instead to limit yourself to IPv6.
	consensus.UseIPProtocol(proto)
	// Get your IP,
	return consensus.ExternalIP()
}
