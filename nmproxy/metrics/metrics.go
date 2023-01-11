package metrics

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/gravitl/netclient/nmproxy/models"
)

func init() {
	go DumpMetrics()
}

// lock for metrics map
var metricsMapLock = &sync.RWMutex{}

// metrics data map
var metricsHostMap = make(map[string]*models.Metric)

// GetMetric - fetches the metric data for the peer
func GetMetric(peerKey string) models.Metric {
	metric := models.Metric{}
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	if m, ok := metricsHostMap[peerKey]; ok {
		metric = *m
	}
	return metric
}

// UpdateMetric - updates metric data for the peer
func UpdateMetric(peerKey string, metric *models.Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	metricsHostMap[peerKey] = metric
}

// ResetMetricsForPeer - reset metrics for peer
func ResetMetricsForPeer(peerKey string) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	delete(metricsHostMap, peerKey)
}

func DumpMetrics() {
	for {
		time.Sleep(time.Minute)
		out, _ := json.MarshalIndent(metricsHostMap, "", " ")
		os.WriteFile("/tmp/metrics.json", out, 0755)
	}
}
