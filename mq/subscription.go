package mq

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/mq"
)

// MessageQueue - sets up Message Queue and subsribes/publishes updates to/from server
// the client should subscribe to ALL nodes that exist on server locally
func MessageQueue(ctx context.Context, wg *sync.WaitGroup, server *config.Server) {
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
	opts.AddBroker(server.Broker)
	opts.SetUsername(server.MQUserName)
	opts.SetPassword(server.MQPassword)
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
			node := node
			setSubscriptions(client, &node)
		}
		setHostSubscription(client, server.Name)
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
		}
	}
	if connecterr != nil {
		logger.Log(0, "failed to establish connection to broker: ", connecterr.Error())
		return connecterr
	}
	if err := PublishHostUpdate(server.Name, models.Acknowledgement); err != nil {
		logger.Log(0, "failed to send initial ACK to server", server.Name, err.Error())
	} else {
		logger.Log(2, "successfully requested ACK on server", server.Name)
	}
	return nil
}

// SetMQTTSingenton - creates a connection to broker for single use (ie to publish a message)
// only to be called from cli (eg. connect/disconnect, join, leave) and not from daemon ---
func SetupMQTTSingleton(server *config.Server, publishOnly bool) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(server.Broker)
	opts.SetUsername(server.MQUserName)
	opts.SetPassword(server.MQPassword)
	opts.SetClientID(server.MQID.String())
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second << 2)
	opts.SetKeepAlive(time.Minute >> 1)
	opts.SetWriteTimeout(time.Minute)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		if !publishOnly {
			logger.Log(0, "mqtt connect handler")
			nodes := config.GetNodes()
			for _, node := range nodes {
				node := node
				setSubscriptions(client, &node)
			}
			setHostSubscription(client, server.Name)
		}
		logger.Log(1, "successfully connected to", server.Broker)
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
		logger.Log(0, "unable to connect to broker,", server.Broker+",", "retrying...")
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
	logger.Log(3, fmt.Sprintf("subscribed to host updates  host/update/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostUpdate)); token.Wait() && token.Error() != nil {
		logger.Log(0, "MQ host sub: ", hostID.String(), token.Error().Error())
		return
	}
	logger.Log(3, fmt.Sprintf("subcribed to dns updates dns/update/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("dns/update/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(dnsUpdate)); token.Wait() && token.Error() != nil {
		logger.Log(0, "MQ host sub: ", hostID.String(), token.Error().Error())
		return
	}
	logger.Log(3, fmt.Sprintf("subcribed to all dns updates dns/all/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("dns/all/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(dnsAll)); token.Wait() && token.Error() != nil {
		logger.Log(0, "MQ host sub: ", hostID.String(), token.Error().Error())
		return
	}
}

// setSubcriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setSubscriptions(client mqtt.Client, node *config.Node) {
	if token := client.Subscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID), 0, mqtt.MessageHandler(NodeUpdate)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(0, "network:", node.Network, "connection timeout")
		} else {
			logger.Log(0, "network:", node.Network, token.Error().Error())
		}
		return
	}
	logger.Log(3, fmt.Sprintf("subscribed to peer updates peers/%s/%s", node.Network, node.ID))
}

// on a delete usually, pass in the nodecfg to unsubscribe client broker communications
// for the node in nodeCfg
func unsubscribeNode(client mqtt.Client, node *config.Node) {
	var ok = true
	if token := client.Unsubscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from updates for node ", node.ID.String(), "\n", "connection timeout")
		} else {
			logger.Log(1, "network:", node.Network, "unable to unsubscribe from updates for node ", node.ID.String(), "\n", token.Error().Error())
		}
		ok = false
	} // peer updates belong to host now

	if ok {
		logger.Log(1, "network:", node.Network, "successfully unsubscribed node ", node.ID.String())
	}
}

// unsubscribe client broker communications for host topics
func unsubscribeHost(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	logger.Log(3, fmt.Sprintf("removing subscription for host peer updates peers/host/%s/%s", hostID.String(), server))
	if token := client.Unsubscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		logger.Log(0, "unable to unsubscribe from host peer updates: ", hostID.String(), token.Error().Error())
		return
	}
	logger.Log(3, fmt.Sprintf("removing subscription for host updates  host/update/%s/%s", hostID.String(), server))
	if token := client.Unsubscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server)); token.WaitTimeout(mq.MQ_TIMEOUT*time.Second) && token.Error() != nil {
		logger.Log(0, "unable to unsubscribe from host updates: ", hostID.String(), token.Error().Error())
		return
	}
}
