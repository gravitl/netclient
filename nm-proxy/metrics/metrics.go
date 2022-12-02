package metrics

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

/*
1. Create metrics packet--> packet with identifier to track latency, errors.

*/

type Metric struct {
	LastRecordedLatency uint64
	ConnectionStatus    bool
	TrafficSent         float64
	TrafficRecieved     float64
}

type MetricsPayload struct {
	MetricType MetricsUpdateType
	Value      interface{}
}

type MetricsUpdateType uint32

const (
	LatencyUpdate         MetricsUpdateType = 1
	TrafficSentUpdate     MetricsUpdateType = 2
	TrafficRecievedUpdate MetricsUpdateType = 3
)

var metricsMapLock = &sync.RWMutex{}

var metricsNetworkMap = make(map[string]map[string]*Metric)

func init() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			printMetrics()
		}
	}()
}

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

func UpdateMetric(network, peerKey string, metric *Metric) {
	metricsMapLock.Lock()
	defer metricsMapLock.Unlock()
	metricsNetworkMap[network][peerKey] = metric
}

func printMetrics() {
	metricsMapLock.RLock()
	defer metricsMapLock.RUnlock()
	data, err := json.MarshalIndent(metricsNetworkMap, "", " ")
	if err != nil {
		return
	}
	os.WriteFile("/tmp/metrics.json", data, 0755)

}
