package metrics

import (
	"sync"

	"github.com/gravitl/netclient/nmproxy/models"
)

// lock for metrics map
var metricsMapLock = &sync.RWMutex{}

// metrics data map
var metricsNetworkMap = make(map[string]map[string]*models.Metric)

// GetMetric - fetches the metric data for the peer
func GetMetric(network, peerKey string) models.Metric {
	metric := models.Metric{}
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	if metricsMap, ok := metricsNetworkMap[network]; ok {
		if m, ok := metricsMap[peerKey]; ok {
			metric = *m
		}
	} else {
		metricsNetworkMap[network] = make(map[string]*models.Metric)
	}
	return metric
}

// UpdateMetric - updates metric data for the peer
func UpdateMetric(network, peerKey string, metric *models.Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	if _, ok := metricsNetworkMap[network]; !ok {
		metricsNetworkMap[network] = make(map[string]*models.Metric)
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
