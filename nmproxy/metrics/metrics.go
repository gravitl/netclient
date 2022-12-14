package metrics

import (
	"sync"
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

// UpdateMetric - updates metric data for the peer
func UpdateMetric(network, peerKey string, metric *Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
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
