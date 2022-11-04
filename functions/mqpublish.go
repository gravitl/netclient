package functions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloverstd/tcping/ping"
	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
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

	netclient := config.Netclient
	//should not be required
	config.GetNodes()
	config.GetServers()
	logger.Log(3, "checkin with server(s) for all networks")
	if len(config.Nodes) == 0 {
		logger.Log(0, "skipping checkin: no nodes configured")
		return
	}
	for network, node := range config.Nodes {
		server := config.Servers[node.Server]
		// check for nftables present if on Linux
		if ncutils.IsLinux() {
			if ncutils.IsNFTablesPresent() {
				netclient.FirewallInUse = models.FIREWALL_NFTABLES
			} else {
				netclient.FirewallInUse = models.FIREWALL_IPTABLES
			}
		} else {
			// defaults to iptables for now, may need another default for non-Linux OSes
			netclient.FirewallInUse = models.FIREWALL_IPTABLES
		}
		if node.Connected {
			if !node.IsStatic {
				extIP, err := ncutils.GetPublicIP(server.API)
				if err != nil {
					logger.Log(1, "error encountered checking public ip addresses: ", err.Error())
				}
				if node.EndpointIP.String() != extIP && extIP != "" {
					logger.Log(1, "network:", network, "endpoint has changed from ", node.EndpointIP.String(), " to ", extIP)
					node.EndpointIP = net.ParseIP(extIP)
					if err := PublishNodeUpdate(&node); err != nil {
						logger.Log(0, "network:", network, "could not publish endpoint change")
					}
				}
				intIP, err := getPrivateAddr()
				if err != nil {
					logger.Log(1, "network:", network, "error encountered checking private ip addresses: ", err.Error())
				}
				if node.LocalAddress.String() != intIP.String() && intIP.IP != nil {
					logger.Log(1, "network:", network, "local Address has changed from ", node.LocalAddress.String(), " to ", intIP.String())
					node.LocalAddress = intIP
					if err := PublishNodeUpdate(&node); err != nil {
						logger.Log(0, "Network: ", network, " could not publish local address change")
					}
				}
				_ = UpdateLocalListenPort(&node)

			} else if node.IsLocal && node.LocalRange.IP != nil {
				localIP, err := ncutils.GetLocalIP(node.LocalRange)
				if err != nil {
					logger.Log(1, "network:", network, "error encountered checking local ip addresses: ", err.Error())
				}
				if node.EndpointIP.String() != localIP.IP.String() && localIP.IP != nil {
					logger.Log(1, "network:", network, "endpoint has changed from "+node.EndpointIP.String()+" to ", localIP.String())
					node.EndpointIP = localIP.IP
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
			logger.Log(0, "collecting metrics for node", node.Name)
			publishMetrics(&node)
		}
	}
}

// PublishNodeUpdates -- pushes node to broker
func PublishNodeUpdate(node *config.Node) error {
	oldNode := config.ConvertToOldNode(node)
	log.Println("publish node update")
	//pretty.Println("node: ", node)
	//pretty.Println("oldnode: ", oldNode)
	data, err := json.Marshal(oldNode)
	if err != nil {
		return err
	}
	if err = publish(node, fmt.Sprintf("update/%s", node.ID), data, 1); err != nil {
		return err
	}

	logger.Log(0, "network:", node.Network, "sent a node update to server for node", node.Name, ", ", node.ID)
	return nil
}

// Hello -- ping the broker to let server know node it's alive and well
func Hello(node *config.Node) {
	var checkin models.NodeCheckin
	checkin.Version = ncutils.Version
	checkin.Connected = config.FormatBool(node.Connected)
	data, err := json.Marshal(checkin)
	if err != nil {
		logger.Log(0, "unable to marshal checkin data", err.Error())
		return
	}
	if err := publish(node, fmt.Sprintf("ping/%s", node.ID), data, 0); err != nil {
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
	token, err := Authenticate(node)
	if err != nil {
		logger.Log(1, "failed to authenticate when publishing metrics", err.Error())
		return
	}
	server := config.Servers[node.Server]
	url := fmt.Sprintf("https://%s/api/nodes/%s/%s", server.API, node.Network, node.ID)
	endpoint := httpclient.JSONEndpoint[models.NodeGet]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      models.NodeGet{},
	}
	response, err := endpoint.GetJSON(models.NodeGet{})
	if err != nil {
		logger.Log(1, "failed to read from server during metrics publish", err.Error())
		return
	}
	nodeGET := response.(models.NodeGet)

	metrics, err := metrics.Collect(node.Interface, nodeGET.PeerIDs)
	if err != nil {
		logger.Log(0, "failed metric collection for node", node.Name, err.Error())
	}
	metrics.Network = node.Network
	metrics.NodeName = node.Name
	metrics.NodeID = node.ID
	metrics.IsServer = "no"
	data, err := json.Marshal(metrics)
	if err != nil {
		logger.Log(0, "something went wrong when marshalling metrics data for node", node.Name, err.Error())
	}

	if err = publish(node, fmt.Sprintf("metrics/%s", node.ID), data, 1); err != nil {
		logger.Log(0, "error occurred during publishing of metrics on node", node.Name, err.Error())
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
		logger.Log(0, "published metrics for node", node.Name)
	}
}

// node cfg is required  in order to fetch the traffic keys of that node for encryption
func publish(node *config.Node, dest string, msg []byte, qos byte) error {
	// setup the keys
	serverPubKey, err := ncutils.ConvertBytesToKey(node.TrafficKeys.Server)
	if err != nil {
		return err
	}

	encrypted, err := Chunk(msg, serverPubKey, node.TrafficPrivateKey)
	if err != nil {
		return err
	}
	mqclient, ok := ServerSet[node.Server]
	if !ok {
		return errors.New("unable to publish ... no mqclient")
	}
	if token := mqclient.Publish(dest, qos, false, encrypted); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
		logger.Log(0, "could not connect to broker at "+node.Server)
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

// publishes a message to server to update peers on this peer's behalf
func publishSignal(node *config.Node, signal byte) error {
	if err := publish(node, fmt.Sprintf("signal/%s", node.ID), []byte{signal}, 1); err != nil {
		return err
	}
	return nil
}
