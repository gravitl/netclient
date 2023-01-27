package functions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloverstd/tcping/ping"
	"github.com/devilcove/httpclient"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	proxyCfg "github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic/metrics"
	"github.com/gravitl/netmaker/models"
)

var metricsCache = new(sync.Map)

const (
	// ACK - acknowledgement signal for MQ
	ACK = 1
	// DONE - done signal for MQ
	DONE = 2
	// CheckInInterval - interval in minutes for mq checkins
	CheckInInterval = 1
)

// Checkin  -- go routine that checks for public or local ip changes, publishes changes
//
//	if there are no updates, simply "pings" the server as a checkin
func Checkin(ctx context.Context, wg *sync.WaitGroup) {
	logger.Log(2, "starting checkin goroutine")
	defer wg.Done()
	ticker := time.NewTicker(time.Minute * CheckInInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Log(0, "checkin routine closed")
			return
		case <-ticker.C:
			for server, mqclient := range ServerSet {
				if !mqclient.IsConnected() {
					logger.Log(0, "MQ client is not connected, skipping checkin for server", server)
					continue
				}
			}
			for server, mqclient := range ServerSet {
				if mqclient == nil {
					logger.Log(0, "MQ client is not configured, skipping checkin for server", server)
					continue
				}
			}
			checkin()
		}
	}
}

func checkin() {

	host := config.Netclient()
	//should not be required
	config.ReadNodeConfig()
	config.ReadServerConf()
	logger.Log(3, "checkin with server(s) for all networks")
	for network, node := range config.GetNodes() {
		server := config.GetServer(node.Server)
		if node.Connected {
			if !config.Netclient().IsStatic {
				extIP, err := ncutils.GetPublicIP(server.API)
				if err != nil {
					logger.Log(1, "error encountered checking public ip addresses: ", err.Error())
				}
				if config.Netclient().EndpointIP.String() != extIP && extIP != "" {
					logger.Log(1, "network:", network, "endpoint has changed from ", config.Netclient().EndpointIP.String(), " to ", extIP)
					config.Netclient().EndpointIP = net.ParseIP(extIP)
					if err := PublishNodeUpdate(&node); err != nil {
						logger.Log(0, "network:", network, "could not publish endpoint change")
					}
				}

			} else if node.IsLocal {
				intIP, err := getPrivateAddr()
				if err != nil {
					logger.Log(1, "network:", network, "error encountered checking private ip addresses: ", err.Error())
				}
				if !config.Netclient().EndpointIP.Equal(intIP.IP) {
					logger.Log(1, "network:", network, "endpoint has changed from "+config.Netclient().EndpointIP.String()+" to ", intIP.IP.String())
					config.Netclient().EndpointIP = intIP.IP
					if err := PublishNodeUpdate(&node); err != nil {
						logger.Log(0, "network:", network, "could not publish localip change")
					}
				}
			}
		}
		//check version
		//if node.Version != ncutils.Version {
		//node.Version = ncutils.Version
		//config.Write(&nodeCfg, nodeCfg.Network)
		//}
		Hello(&node)
		if server.Is_EE && node.Connected {
			logger.Log(0, "collecting metrics for node", host.Name)
			publishMetrics(&node)
		}
	}
	_ = UpdateHostSettings()
}

// PublishNodeUpdate -- pushes node to broker
func PublishNodeUpdate(node *config.Node) error {
	server := config.GetServer(node.Server)
	if server.Name == "" {
		return errors.New("no server for " + node.Network)
	}
	data, err := json.Marshal(node)
	if err != nil {
		return err
	}
	if err = publish(node.Server, fmt.Sprintf("update/%s", node.ID), data, 1); err != nil {
		return err
	}

	logger.Log(0, "network:", node.Network, "sent a node update to server for node", config.Netclient().Name, ", ", node.ID.String())
	return nil
}

// PublishGlobalHostUpdate - publishes host updates to all the servers host is registered.
func PublishGlobalHostUpdate(hostAction models.HostMqAction) error {
	servers := config.GetServers()
	hostCfg := config.Netclient()
	hostUpdate := models.HostUpdate{
		Action: hostAction,
		Host:   hostCfg.Host,
	}
	data, err := json.Marshal(hostUpdate)
	if err != nil {
		return err
	}
	for _, server := range servers {
		if err = publish(server, fmt.Sprintf("host/serverupdate/%s", hostCfg.ID.String()), data, 1); err != nil {
			logger.Log(1, "failed to publish host update to: ", server, err.Error())
			continue
		}
	}
	return nil
}

// PublishHostUpdate - publishes host updates to server
func PublishHostUpdate(server string, hostAction models.HostMqAction) error {
	hostCfg := config.Netclient()
	hostUpdate := models.HostUpdate{
		Action: hostAction,
		Host:   hostCfg.Host,
	}
	data, err := json.Marshal(hostUpdate)
	if err != nil {
		return err
	}
	if err = publish(server, fmt.Sprintf("host/serverupdate/%s", hostCfg.ID.String()), data, 1); err != nil {
		return err
	}
	return nil
}

// Hello -- ping the broker to let server know node it's alive and well
func Hello(node *config.Node) {
	var checkin models.NodeCheckin
	checkin.Version = config.Version
	checkin.Connected = node.Connected
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			config.Netclient().Interfaces = *ip
			if err := config.WriteNodeConfig(); err != nil {
				logger.Log(0, "error saving node map", err.Error())
			}
		}
	}
	checkin.Ifaces = config.Netclient().Interfaces
	data, err := json.Marshal(checkin)
	if err != nil {
		logger.Log(0, "unable to marshal checkin data", err.Error())
		return
	}
	if err := publish(node.Server, fmt.Sprintf("ping/%s", node.ID), data, 0); err != nil {
		logger.Log(0, fmt.Sprintf("Network: %s error publishing ping, %v", node.Network, err))
		logger.Log(0, "running pull on "+node.Network+" to reconnect")
		_, err := Pull(node.Network, true)
		if err != nil {
			logger.Log(0, "could not run pull on "+node.Network+", error: "+err.Error())
		}
	} else {
		logger.Log(3, "checkin for", node.Network, "complete")
	}
}

// publishMetrics - publishes the metrics of a given nodecfg
func publishMetrics(node *config.Node) {
	server := config.GetServer(node.Server)
	token, err := Authenticate(server.API, config.Netclient())
	if err != nil {
		logger.Log(1, "failed to authenticate when publishing metrics", err.Error())
		return
	}
	url := fmt.Sprintf("https://%s/api/nodes/%s/%s", server.API, node.Network, node.ID)
	endpoint := httpclient.JSONEndpoint[models.NodeGet, models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      models.NodeGet{},
		ErrorResponse: models.ErrorResponse{},
	}
	response, errData, err := endpoint.GetJSON(models.NodeGet{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "status error calling ", endpoint.URL, errData.Message)
			return
		}
		logger.Log(1, "failed to read from server during metrics publish", err.Error())
		return
	}
	nodeGET := response

	metrics, err := metrics.Collect(ncutils.GetInterfaceName(), node.Server, nodeGET.Node.Network, nodeGET.PeerIDs)
	if err != nil {
		logger.Log(0, "failed metric collection for node", config.Netclient().Name, err.Error())
	}
	metrics.Network = node.Network
	metrics.NodeName = config.Netclient().Name
	metrics.NodeID = node.ID.String()
	data, err := json.Marshal(metrics)
	if err != nil {
		logger.Log(0, "something went wrong when marshalling metrics data for node", config.Netclient().Name, err.Error())
	}

	if err = publish(node.Server, fmt.Sprintf("metrics/%s", node.ID), data, 1); err != nil {
		logger.Log(0, "error occurred during publishing of metrics on node", config.Netclient().Name, err.Error())
		logger.Log(0, "aggregating metrics locally until broker connection re-established")
		val, ok := metricsCache.Load(node.ID)
		if !ok {
			metricsCache.Store(node.ID, data)
		} else {
			var oldMetrics models.Metrics
			err = json.Unmarshal(val.([]byte), &oldMetrics)
			if err == nil {
				for k := range oldMetrics.Connectivity {
					currentMetric := metrics.Connectivity[k]
					if currentMetric.Latency == 0 {
						currentMetric.Latency = oldMetrics.Connectivity[k].Latency
					}
					currentMetric.Uptime += oldMetrics.Connectivity[k].Uptime
					currentMetric.TotalTime += oldMetrics.Connectivity[k].TotalTime
					metrics.Connectivity[k] = currentMetric
				}
				newData, err := json.Marshal(metrics)
				if err == nil {
					metricsCache.Store(node.ID, newData)
				}
			}
		}
	} else {
		metricsCache.Delete(node.ID)
		logger.Log(0, "published metrics for node", config.Netclient().Name)
	}
}

func publish(serverName, dest string, msg []byte, qos byte) error {
	// setup the keys
	server := config.GetServer(serverName)
	serverPubKey, err := ncutils.ConvertBytesToKey(server.TrafficKey)
	if err != nil {
		return err
	}
	privateKey, err := ncutils.ConvertBytesToKey(config.Netclient().TrafficKeyPrivate)
	if err != nil {
		return err
	}
	encrypted, err := Chunk(msg, serverPubKey, privateKey)
	if err != nil {
		return err
	}
	mqclient, ok := ServerSet[serverName]
	if !ok {
		return errors.New("unable to publish ... no mqclient")
	}
	if token := mqclient.Publish(dest, qos, false, encrypted); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
		logger.Log(0, "could not connect to broker at "+serverName)
		var err error
		if token.Error() == nil {
			err = errors.New("connection timeout")
		} else {
			err = token.Error()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func checkBroker(broker string, port string) error {
	if broker == "" {
		return errors.New("error: broker address is blank")
	}
	if port == "" {
		return errors.New("error: broker port is blank")
	}
	_, err := net.LookupIP(broker)
	if err != nil {
		return errors.New("nslookup failed for broker ... check dns records")
	}
	pinger := ping.NewTCPing()
	intPort, err := strconv.Atoi(port)
	if err != nil {
		logger.Log(1, "error converting port to int: "+err.Error())
	}
	pinger.SetTarget(&ping.Target{
		Protocol: ping.TCP,
		Host:     broker,
		Port:     intPort,
		Counter:  3,
		Interval: 1 * time.Second,
		Timeout:  2 * time.Second,
	})
	pingerDone := pinger.Start()
	<-pingerDone
	if pinger.Result().SuccessCounter == 0 {
		return errors.New("unable to connect to broker port ... check netmaker server and firewalls")
	}
	return nil
}

// UpdateHostSettings - checks local host settings, if different, mod config and publish
func UpdateHostSettings() error {
	var err error
	publishMsg := false
	ifacename := ncutils.GetInterfaceName()
	var proxylistenPort int
	var proxypublicport int
	if config.Netclient().ProxyEnabled {
		proxylistenPort = proxyCfg.GetCfg().HostInfo.PrivPort
		proxypublicport = proxyCfg.GetCfg().HostInfo.PubPort
		if proxylistenPort == 0 {
			proxylistenPort = models.NmProxyPort
		}
		if proxypublicport == 0 {
			proxypublicport = models.NmProxyPort
		}
	}
	localPort, err := GetLocalListenPort(ifacename)
	if err != nil {
		logger.Log(1, "error encountered checking local listen port: ", ifacename, err.Error())
	} else if config.Netclient().ListenPort != localPort && localPort != 0 {
		logger.Log(1, "local port has changed from ", strconv.Itoa(config.Netclient().ListenPort), " to ", strconv.Itoa(localPort))
		config.Netclient().ListenPort = localPort
		publishMsg = true
	}
	if config.Netclient().ProxyEnabled {

		if config.Netclient().ProxyListenPort != proxylistenPort {
			logger.Log(1, fmt.Sprint("proxy listen port has changed from ", config.Netclient().ProxyListenPort, " to ", proxylistenPort))
			config.Netclient().ProxyListenPort = proxylistenPort
			publishMsg = true
		}
		if config.Netclient().PublicListenPort != proxypublicport {
			logger.Log(1, fmt.Sprint("public listen port has changed from ", config.Netclient().PublicListenPort, " to ", proxypublicport))
			config.Netclient().PublicListenPort = proxypublicport
			publishMsg = true
		}
	}
	if proxyCfg.GetCfg().IsBehindNAT() && !config.Netclient().ProxyEnabled {
		logger.Log(0, "Host is behind NAT, enabling proxy...")
		config.Netclient().ProxyEnabled = true
		publishMsg = true
	}
	if publishMsg {
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		logger.Log(0, "publishing global host update for port changes")
		if err := PublishGlobalHostUpdate(models.UpdateHost); err != nil {
			logger.Log(0, "could not publish local port change", err.Error())
		}
	}

	return err
}

// publishes a message to server to update peers on this peer's behalf
func publishSignal(node *config.Node, signal byte) error {
	if err := publish(node.Server, fmt.Sprintf("signal/%s", node.ID), []byte{signal}, 1); err != nil {
		return err
	}
	return nil
}

// publishes a blank message to the topic to clear the unwanted retained message
func clearRetainedMsg(client mqtt.Client, topic string) {
	if token := client.Publish(topic, 0, true, []byte{}); token.Error() != nil {
		logger.Log(0, "failed to clear retained message: ", topic, token.Error().Error())
	}
}
