package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/nm-proxy/wg"
)

// Metric - struct for metric data
type Metric struct {
	LastRecordedLatency uint64  `json:"last_recorded_latency"`
	ConnectionStatus    bool    `json:"connection_status"`
	TrafficSent         float64 `json:"traffic_sent"`     // stored in MB
	TrafficRecieved     float64 `json:"traffic_recieved"` // stored in MB
}

// lock for metrics map
var metricsMapLock = &sync.RWMutex{}

// metrics data map
var metricsNetworkMap = make(map[string]map[string]*Metric)

// GetMetric - fetches the metric data for the peer
func GetMetric(network, peerKey string) Metric {
	metric := Metric{}
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	if metricsMap, ok := metricsNetworkMap[network]; ok {
		if m, ok := metricsMap[peerKey]; ok {
			metric = *m
		}
	} else {
		metricsNetworkMap[network] = make(map[string]*Metric)
	}
	return metric
}

func StartMetricsCollectionForNoProxyPeers(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Minute * 1)
			noProxyPeers := config.GetCfg().GetNoProxyPeers()
			for peerPubKey, peerInfo := range noProxyPeers {
				go collectMetricsForNoProxyPeer(peerPubKey, *peerInfo)
			}
		}
	}
}

func collectMetricsForNoProxyPeer(peerKey string, peerInfo models.RemotePeer) {

	devPeer, err := wg.GetPeer(peerInfo.Interface, peerKey)
	if err != nil {
		return
	}
	connectionStatus := PeerConnectionStatus(peerInfo.Address.String())
	metric := Metric{
		LastRecordedLatency: 999,
		ConnectionStatus:    connectionStatus,
	}
	metric.TrafficRecieved = float64(devPeer.ReceiveBytes) / (1 << 20) // collected in MB
	metric.TrafficSent = float64(devPeer.TransmitBytes) / (1 << 20)    // collected in MB
	UpdateMetric(peerInfo.Network, peerInfo.PeerKey, &metric)
	pkt, err := packet.CreateMetricPacket(uuid.New().ID(), peerInfo.Network, config.GetCfg().GetDevicePubKey(), devPeer.PublicKey)
	if err == nil {
		conn := config.GetCfg().GetServerConn()
		if conn != nil {
			_, err = conn.WriteToUDP(pkt, peerInfo.Endpoint)
			if err != nil {
				logger.Log(1, "Failed to send to metric pkt: ", err.Error())
			}
		}

	}
}

// UpdateMetric - updates metric data for the peer
func UpdateMetric(network, peerKey string, metric *Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	if _, ok := metricsNetworkMap[network]; !ok {
		metricsNetworkMap[network] = make(map[string]*Metric)
	}
	metricsNetworkMap[network][peerKey] = metric
}

// ResetMetricsForPeer - reset metrics for peer
func ResetMetricsForPeer(network, peerKey string) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	if _, ok := metricsNetworkMap[network]; ok {
		delete(metricsNetworkMap[network], peerKey)
	}

}
