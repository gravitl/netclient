package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gravitl/netclient/nm-proxy/common"
)

// Metric - struct for metric data
type Metric struct {
	LastRecordedLatency uint64
	ConnectionStatus    bool
	TrafficSent         float64
	TrafficRecieved     float64
}

// lock for metrics map
var metricsMapLock = &sync.RWMutex{}

// metrics data map
var metricsNetworkMap = make(map[string]map[string]*Metric)

func init() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			dumpMetricsToFile()
		}
	}()
}

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

func dumpMetricsToFile() {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	data, err := json.MarshalIndent(metricsNetworkMap, "", " ")
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(common.GetDataPath(), "metrics.json"), data, 0755)

}
