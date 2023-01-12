package metrics

import (
	"sync"

	"github.com/gravitl/netclient/nmproxy/models"
)

// lock for metrics map
var metricsMapLock = &sync.RWMutex{}

// metrics data map
var metricsPeerMap = make(map[string]map[string]*models.Metric)

// GetMetricByServer - get metric data of peers by server
func GetMetricByServer(server string) map[string]*models.Metric {
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	if _, ok := metricsPeerMap[server]; !ok {
		metricsPeerMap[server] = make(map[string]*models.Metric)
	}
	return metricsPeerMap[server]
}

// GetMetric - fetches the metric data for the peer
func GetMetric(server, peerKey string) models.Metric {
	metric := models.Metric{}
	peerMetricMap := GetMetricByServer(server)
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	if m, ok := peerMetricMap[peerKey]; ok && m != nil {
		metric = *m
	}
	return metric
}

// UpdateMetric - updates metric data for the peer
func UpdateMetric(server, peerKey string, metric *models.Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	if metricsPeerMap[server] == nil {
		metricsPeerMap[server] = make(map[string]*models.Metric)
	}
	metricsPeerMap[server][peerKey] = metric
}

// UpdateMetricByPeer - updates metrics data by peer public key
func UpdateMetricByPeer(peerKey string, metric *models.Metric, onlyTraffic bool) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	for server, peerKeyMap := range metricsPeerMap {
		if peerMetric, ok := peerKeyMap[peerKey]; ok {
			peerMetric.TrafficRecieved += metric.TrafficRecieved
			peerMetric.TrafficSent += metric.TrafficSent
			if !onlyTraffic {
				peerMetric.LastRecordedLatency = metric.LastRecordedLatency
			}

			metricsPeerMap[server][peerKey] = peerMetric
		}
	}
}

// ResetMetricsForPeer - reset metrics for peer
func ResetMetricsForPeer(server, peerKey string) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	delete(metricsPeerMap[server], peerKey)
}

// ResetMetricForNode - resets node level metrics
func ResetMetricForNode(server, peerKey, peerID string) {
	metric := GetMetric(server, peerKey)
	metricsMapLock.Lock()
	delete(metric.NodeConnectionStatus, peerID)
	metricsMapLock.Unlock()
	UpdateMetric(server, peerKey, &metric)
}
