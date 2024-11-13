package functions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

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
	ipTicker := time.NewTicker(time.Second * 15)
	defer ipTicker.Stop()
	checkinTicker := time.NewTicker(time.Minute * 4)
	defer checkinTicker.Stop()
	mi := 15
	server := config.GetServer(config.CurrServer)
	if server != nil {
		i, err := strconv.Atoi(server.MetricInterval)
		if err == nil && i > 0 {
			mi = i
		}
	}
	metricTicker := time.NewTicker(time.Minute * time.Duration(mi))
	defer metricTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Log(0, "checkin routine closed")
			return
		case <-metricTicker.C:
			if config.CurrServer == "" {
				continue
			}
			go callPublishMetrics(true)
		case <-checkinTicker.C:
			if config.CurrServer == "" {
				continue
			}
			hostServerUpdate(models.HostUpdate{Action: models.CheckIn})
		case <-ticker.C:
			if config.CurrServer == "" {
				continue
			}
			if err := UpdateHostSettings(true); err != nil {
				slog.Warn("failed to update host settings", err.Error())
			}
		case <-ipTicker.C:
			// this ticker is used to detect network changes, and publish new public ip to peers
			// if config.Netclient().CurrGwNmIP is not nil, it's an InetClient, then it skips the network change detection
			if !config.Netclient().IsStatic && config.Netclient().CurrGwNmIP == nil {
				restart := false
				ip4, _, _ := holePunchWgPort(4, 0)
				if ip4 != nil && !ip4.IsUnspecified() && !config.HostPublicIP.Equal(ip4) {
					slog.Warn("IP CHECKIN", "ipv4", ip4, "HostPublicIP", config.HostPublicIP)
					config.HostPublicIP = ip4
					restart = true
				} else if ip4 == nil && config.HostPublicIP != nil {
					slog.Warn("IP CHECKIN", "ipv4", ip4, "HostPublicIP", config.HostPublicIP)
					config.HostPublicIP = nil
					restart = true
				}
				ip6, _, _ := holePunchWgPort(6, 0)
				if ip6 != nil && !ip6.IsUnspecified() && !config.HostPublicIP6.Equal(ip6) {
					slog.Warn("IP CHECKIN", "ipv6", ip6, "HostPublicIP6", config.HostPublicIP6)
					config.HostPublicIP6 = ip6
					restart = true
				} else if ip6 == nil && config.HostPublicIP6 != nil {
					slog.Warn("IP CHECKIN", "ipv6", ip6, "HostPublicIP6", config.HostPublicIP6)
					config.HostPublicIP6 = nil
					restart = true
				}
				if restart {
					if err := UpdateHostSettings(true); err != nil {
						slog.Warn("failed to update host settings", err.Error())
					}
					logger.Log(0, "restarting netclient due to network changes...")
					daemon.HardRestart()
				}
			}
		}

	}
}

// hostServerUpdate - used to send host updates to server via restful api
func hostServerUpdate(hu models.HostUpdate) error {

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server config not found")
	}
	host := config.Netclient()
	if host == nil {
		return fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return err
	}
	hu.Host = host.Host
	endpoint := httpclient.JSONEndpoint[models.SuccessResponse, models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         fmt.Sprintf("/api/v1/fallback/host/%s", host.ID.String()),
		Method:        http.MethodPut,
		Data:          hu,
		Authorization: "Bearer " + token,
		ErrorResponse: models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(models.SuccessResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Error("error sending host update to server", "code", strconv.Itoa(errData.Code), "error", errData.Message)
		}
		return err
	}
	return nil
}

func checkin() {
	if err := PublishHostUpdate(config.CurrServer, models.HostMqAction(models.CheckIn)); err != nil {
		logger.Log(0, "error publishing checkin", err.Error())
		return
	}
}

// PublishNodeUpdate -- pushes node to broker
func PublishNodeUpdate(node *config.Node) error {
	server := config.GetServer(node.Server)
	if server == nil || server.Name == "" {
		return errors.New("no server for " + node.Network)
	}
	data, err := json.Marshal(node)
	if err != nil {
		return err
	}
	if err = publish(node.Server, fmt.Sprintf("update/%s/%s", node.Server, node.ID), data, 1); err != nil {
		return err
	}

	logger.Log(0, "network:", node.Network, "sent a node update to server for node", config.Netclient().Name, ", ", node.ID.String())
	return nil
}

// publishPeerSignal - publishes peer signal
func publishPeerSignal(server string, signal models.Signal) error {
	hostCfg := config.Netclient()
	hostUpdate := models.HostUpdate{
		Action: models.SignalHost,
		Host:   hostCfg.Host,
		Signal: signal,
	}
	data, err := json.Marshal(hostUpdate)
	if err != nil {
		return err
	}
	if err = publish(server, fmt.Sprintf("host/serverupdate/%s/%s", server, hostCfg.ID.String()), data, 1); err != nil {
		return err
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
	if err = publish(server, fmt.Sprintf("host/serverupdate/%s/%s", server, hostCfg.ID.String()), data, 1); err != nil {
		return err
	}
	return nil
}

func callPublishMetrics(fallback bool) {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		slog.Warn("server config is nil")
		return
	}

	if server.IsPro {
		serverNodes := config.GetNodes()
		for _, node := range serverNodes {
			node := node
			if node.Connected {
				slog.Debug("collecting metrics for", "network", node.Network)
				go publishMetrics(&node, fallback)
			}
		}
	}
}

// publishMetrics - publishes the metrics of a given nodecfg
func publishMetrics(node *config.Node, fallback bool) {
	server := config.GetServer(node.Server)
	if server == nil {
		return
	}
	token, err := auth.Authenticate(server, config.Netclient())
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

	metrics, err := metrics.Collect(nodeGET.Node.Network, nodeGET.PeerIDs)
	if err != nil {
		logger.Log(0, "failed metric collection for node", config.Netclient().Name, err.Error())
		return
	}
	metrics.Network = node.Network
	metrics.NodeName = config.Netclient().Name
	metrics.NodeID = node.ID.String()
	data, err := json.Marshal(metrics)
	if err != nil {
		logger.Log(0, "something went wrong when marshalling metrics data for node", config.Netclient().Name, err.Error())
		return
	}
	if fallback {
		hostServerUpdate(models.HostUpdate{Action: models.UpdateMetrics, Node: nodeGET.Node, NewMetrics: *metrics})
		return
	}
	if err = publish(node.Server, fmt.Sprintf("metrics/%s/%s", node.Server, node.ID), data, 1); err != nil {
		logger.Log(0, "error occurred during publishing of metrics on node", config.Netclient().Name, err.Error())

	}

}

func publish(serverName, dest string, msg []byte, qos byte) error {
	// setup the keys
	server := config.GetServer(serverName)
	if server == nil {
		return errors.New("server config is nil")
	}
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
	if Mqclient == nil || !Mqclient.IsConnectionOpen() {
		return errors.New("cannot publish ... Mqclient not connected")
	}
	if token := Mqclient.Publish(dest, qos, false, encrypted); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
		logger.Log(0, "could not connect to broker at "+serverName)
		var err error
		if token.Error() == nil {
			err = errors.New("connection timeout")
		} else {
			err = token.Error()
		}
		slog.Error("could not connect to broker at", "server", serverName, "error", err)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateHostSettings - checks local host settings, if different, mod config and publish
func UpdateHostSettings(fallback bool) error {
	_ = config.ReadNodeConfig()
	_ = config.ReadServerConf()
	logger.Log(3, "checkin with server(s)")
	var (
		err           error
		publishMsg    bool
		restartDaemon bool
	)

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server config is nil")
	}
	if !config.Netclient().IsStatic {
		if config.HostPublicIP != nil && !config.HostPublicIP.IsUnspecified() {
			if !config.Netclient().EndpointIP.Equal(config.HostPublicIP) {
				logger.Log(0, "endpoint has changed from", config.Netclient().EndpointIP.String(), "to", config.HostPublicIP.String())
				config.Netclient().EndpointIP = config.HostPublicIP
				publishMsg = true
			}
		} else {
			if config.Netclient().EndpointIP != nil {
				config.Netclient().EndpointIP = nil
				publishMsg = true
			}
		}
	}

	if !config.Netclient().IsStatic {
		if config.HostPublicIP6 != nil && !config.HostPublicIP6.IsUnspecified() {
			if !config.Netclient().EndpointIPv6.Equal(config.HostPublicIP6) {
				logger.Log(0, "endpoint6 has changed from", config.Netclient().EndpointIPv6.String(), "to", config.HostPublicIP6.String())
				config.Netclient().EndpointIPv6 = config.HostPublicIP6
				publishMsg = true
			}
		} else {
			if config.Netclient().EndpointIPv6 != nil {
				config.Netclient().EndpointIPv6 = nil
				publishMsg = true
			}
		}
	}

	if config.WgPublicListenPort != 0 && config.Netclient().WgPublicListenPort != config.WgPublicListenPort {
		if !config.Netclient().IsStaticPort {
			config.Netclient().WgPublicListenPort = config.WgPublicListenPort
		} else {
			config.Netclient().WgPublicListenPort = config.Netclient().ListenPort
		}
		publishMsg = true
	}

	if config.HostNatType != "" && config.Netclient().NatType != config.HostNatType {
		config.Netclient().NatType = config.HostNatType
		publishMsg = true
	}

	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces during check-in", err.Error())
	} else {
		if ip != nil {
			if len(*ip) != len(config.Netclient().Interfaces) {
				config.Netclient().Interfaces = *ip
				publishMsg = true
			}
		}
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else {
		if defaultInterface != config.Netclient().DefaultInterface &&
			defaultInterface != ncutils.GetInterfaceName() {
			publishMsg = true
			config.Netclient().DefaultInterface = defaultInterface
			logger.Log(0, "default interface has changed to", defaultInterface)
		}
	}
	if config.FirewallHasChanged() {
		config.SetFirewall()
		publishMsg = true
	}
	if publishMsg {
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		slog.Info("publishing host update for endpoint changes")
		if fallback {
			hostServerUpdate(models.HostUpdate{Action: models.UpdateHost})
		} else {
			if err := PublishHostUpdate(config.CurrServer, models.UpdateHost); err != nil {
				logger.Log(0, "could not publish endpoint change", err.Error())
			}
		}
	}
	if restartDaemon {
		if err := daemon.Restart(); err != nil {
			slog.Error("failed to restart daemon", "error", err)
		}
	}

	return err
}

// publishes a message to server to update peers on this peer's behalf
func publishSignal(node *config.Node, signal byte) error {
	if err := publish(node.Server, fmt.Sprintf("signal/%s/%s", node.Server, node.ID), []byte{signal}, 1); err != nil {
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
