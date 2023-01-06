package functions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/mq"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const lastNodeUpdate = "lnu"
const lastPeerUpdate = "lpu"

var messageCache = new(sync.Map)
var ServerSet = make(map[string]mqtt.Client)
var ProxyManagerChan = make(chan *models.PeerUpdate)

type cachedMessage struct {
	Message  string
	LastSeen time.Time
}

func startProxy(wg *sync.WaitGroup) context.CancelFunc {

	ctx, cancel := context.WithCancel(context.Background())
	for _, server := range config.Servers {
		wg.Add(1)
		go func(server config.Server) {
			defer wg.Done()
			nmproxy.Start(ctx, ProxyManagerChan, server.StunHost, server.StunPort, false)
		}(server)
		break
	}
	return cancel
}

// Daemon runs netclient daemon
func Daemon() {
	logger.Log(0, "netclient daemon started -- version:", config.Version)
	if err := ncutils.SavePID(); err != nil {
		logger.FatalLog("unable to save PID on daemon startup")
	}
	if err := local.SetIPForwarding(); err != nil {
		logger.Log(0, "unable to set IPForwarding", err.Error())
	}
	wg := sync.WaitGroup{}
	quit := make(chan os.Signal, 1)
	reset := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, os.Interrupt)
	signal.Notify(reset, syscall.SIGHUP)
	cancel := startGoRoutines(&wg)
	proxyWg := sync.WaitGroup{}
	stopProxy := startProxy(&proxyWg)
	for {
		select {
		case <-quit:
			cancel()
			stopProxy()
			proxyWg.Wait()
			logger.Log(0, "shutting down netclient daemon")
			wg.Wait()
			for _, mqclient := range ServerSet {
				if mqclient != nil {
					mqclient.Disconnect(250)
				}
			}
			logger.Log(0, "closing netmaker interface")
			iface := wireguard.GetInterface()
			iface.Close()
			logger.Log(0, "shutdown complete")
			return
		case <-reset:
			logger.Log(0, "received reset")
			cancel()
			wg.Wait()
			for _, mqclient := range ServerSet {
				if mqclient != nil {
					mqclient.Disconnect(250)
				}
			}
			logger.Log(0, "restarting daemon")
			cancel = startGoRoutines(&wg)
			stopProxy = startProxy(&proxyWg)
		}
	}
}

// startGoRoutines starts the daemon goroutines
func startGoRoutines(wg *sync.WaitGroup) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := config.ReadNetclientConfig(); err != nil {
		logger.Log(0, "error reading neclient config file", err.Error())
	}
	if err := config.ReadNodeConfig(); err != nil {
		logger.Log(0, "error reading node map from disk", err.Error())
	}
	if err := config.ReadServerConf(); err != nil {
		logger.Log(0, "errors reading server map from disk", err.Error())
	}
	nodes := config.GetNodes()
	logger.Log(3, "configuring netmaker wireguard interface")
	nc := wireguard.NewNCIface(config.Netclient(), nodes)
	nc.Create()
	nc.Configure()
	wireguard.SetPeers()
	for _, server := range config.Servers {
		logger.Log(1, "started daemon for server ", server.Name)
		wg.Add(1)
		go messageQueue(ctx, wg, &server)
	}
	wg.Add(1)
	go Checkin(ctx, wg)
	return cancel
}

// sets up Message Queue and subsribes/publishes updates to/from server
// the client should subscribe to ALL nodes that exist on server locally
func messageQueue(ctx context.Context, wg *sync.WaitGroup, server *config.Server) {
	defer wg.Done()
	logger.Log(0, "netclient message queue started for server:", server.Name)
	err := setupMQTT(server)
	if err != nil {
		logger.Log(0, "unable to connect to broker", server.Broker, err.Error())
		return
	}
	defer ServerSet[server.Name].Disconnect(250)
	<-ctx.Done()
	logger.Log(0, "shutting down message queue for server", server.Name)
}

// setupMQTT creates a connection to broker
func setupMQTT(server *config.Server) error {
	opts := mqtt.NewClientOptions()
	broker := server.Broker
	port := server.MQPort
	opts.AddBroker(fmt.Sprintf("wss://%s:%s", broker, port))
	opts.SetUsername(server.MQID.String())
	opts.SetPassword(server.Password)
	//opts.SetClientID(ncutils.MakeRandomString(23))
	opts.SetClientID(server.MQID.String())
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second << 2)
	opts.SetKeepAlive(time.Minute >> 1)
	opts.SetWriteTimeout(time.Minute)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		logger.Log(0, "mqtt connect handler")
		nodes := config.GetNodes()
		for _, node := range nodes {
			setSubscriptions(client, &node)
		}
		servers := config.GetServers()
		for _, server := range servers {
			setHostSubscription(client, server)
		}

	})
	opts.SetOrderMatters(true)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		logger.Log(0, "detected broker connection lost for", server.Broker)
	})
	mqclient := mqtt.NewClient(opts)
	ServerSet[server.Name] = mqclient
	var connecterr error
	for count := 0; count < 3; count++ {
		connecterr = nil
		if token := mqclient.Connect(); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
			logger.Log(0, "unable to connect to broker, retrying ...")
			if token.Error() == nil {
				connecterr = errors.New("connect timeout")
			} else {
				connecterr = token.Error()
			}
			if err := checkBroker(server.Broker, server.MQPort); err != nil {
				logger.Log(0, "could not connect to broker", server.Broker, err.Error())
			}
		}
	}
	if connecterr != nil {
		logger.Log(0, "failed to establish connection to broker: ", connecterr.Error())
		return connecterr
	}
	return nil
}

// func setMQTTSingenton creates a connection to broker for single use (ie to publish a message)
// only to be called from cli (eg. connect/disconnect, join, leave) and not from daemon ---
func setupMQTTSingleton(server *config.Server) error {
	opts := mqtt.NewClientOptions()
	broker := server.Broker
	port := server.MQPort
	opts.AddBroker(fmt.Sprintf("wss://%s:%s", broker, port))
	opts.SetUsername(server.MQID.String())
	opts.SetPassword(server.Password)
	opts.SetClientID(server.MQID.String())
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second << 2)
	opts.SetKeepAlive(time.Minute >> 1)
	opts.SetWriteTimeout(time.Minute)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		logger.Log(0, "mqtt connect handler")
		nodes := config.GetNodes()
		for _, node := range nodes {
			setSubscriptions(client, &node)
		}
		servers := config.GetServers()
		for _, server := range servers {
			setHostSubscription(client, server)
		}

	})
	opts.SetOrderMatters(true)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		logger.Log(0, "detected broker connection lost for", server.Broker)
	})
	mqclient := mqtt.NewClient(opts)
	ServerSet[server.Name] = mqclient
	var connecterr error
	if token := mqclient.Connect(); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
		logger.Log(0, "unable to connect to broker, retrying ...")
		if token.Error() == nil {
			connecterr = errors.New("connect timeout")
		} else {
			connecterr = token.Error()
		}
	}
	return connecterr
}

// setHostSubscription sets MQ client subscriptions for host
// should be called for each server host is registered on.
func setHostSubscription(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	logger.Log(3, fmt.Sprintf("subscribed to host peer updates  peers/host/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostPeerUpdate)); token.Wait() && token.Error() != nil {
		logger.Log(0, "MQ host sub: ", hostID.String(), token.Error().Error())
		return
	}
}

// setSubcriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setSubscriptions(client mqtt.Client, node *config.Node) {
	if token := client.Subscribe(fmt.Sprintf("update/%s/%s", node.Network, node.ID), 0, mqtt.MessageHandler(NodeUpdate)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(0, "network:", node.Network, "connection timeout")
		} else {
			logger.Log(0, "network:", node.Network, token.Error().Error())
		}
		return
	}
	logger.Log(3, fmt.Sprintf("subscribed to proxy updates  /%s/%s", node.Network, node.ID))
	if token := client.Subscribe(fmt.Sprintf("proxy/%s/%s", node.Network, node.ID), 0, mqtt.MessageHandler(ProxyUpdate)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(0, "###### network:", node.Network, "connection timeout")
		} else {
			logger.Log(0, "###### network:", node.Network, token.Error().Error())
		}
		return
	}
	logger.Log(3, fmt.Sprintf("subscribed to peer updates peers/%s/%s", node.Network, node.ID))
}

// should only ever use node client configs
func decryptMsg(serverName string, msg []byte) ([]byte, error) {
	if len(msg) <= 24 { // make sure message is of appropriate length
		return nil, fmt.Errorf("recieved invalid message from broker %v", msg)
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
	client.Unsubscribe(fmt.Sprintf("update/%s/%s", node.Network, node.ID))
	var ok = true
	if token := client.Unsubscribe(fmt.Sprintf("update/%s/%s", node.Network, node.ID)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from updates for node ", node.ID.String(), "\n", "connection timeout")
		} else {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from updates for node ", node.ID.String(), "\n", token.Error().Error())
		}
		ok = false
	}
	if token := client.Unsubscribe(fmt.Sprintf("peers/%s/%s", node.Network, node.ID)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from peer updates for node", node.ID.String(), "\n", "connection timeout")
		} else {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from peer updates for node", node.ID.String(), "\n", token.Error().Error())
		}
		ok = false
	}
	if ok {
		logger.Log(1, "network:", node.Network, "successfully unsubscribed node ", node.ID.String())
	}
}

// UpdateKeys -- updates private key and returns new publickey
func UpdateKeys(node *config.Node, host *config.Config, client mqtt.Client) error {
	var err error
	logger.Log(0, "received message to update wireguard keys for network ", node.Network)
	host.PrivateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Log(0, "network:", node.Network, "error generating privatekey ", err.Error())
		return err
	}
	file := config.GetNetclientPath() + "netmaker.conf"
	if err := wireguard.UpdatePrivateKey(file, host.PrivateKey.String()); err != nil {
		logger.Log(0, "network:", node.Network, "error updating wireguard key ", err.Error())
		return err
	}
	host.PublicKey = host.PrivateKey.PublicKey()
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saving netclient config", err.Error())
	}
	PublishNodeUpdate(node)
	return nil
}

// RemoveServer - removes a server from server conf given a specific node
func RemoveServer(node *config.Node) {
	logger.Log(0, "removing server", node.Server, "from mq")
	delete(ServerSet, node.Server)
}
