package functions

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type egressPeer struct {
	PeerKey       string
	EgressRange   string
	Metric        uint32
	EgressGwAddr  net.IPNet
	EgressGwAddr6 net.IPNet
}

// Egress HA watch Thread
var egressRoutes = []models.EgressNetworkRoutes{}
var egressRoutesCacheMutex = &sync.Mutex{}
var haEgressTicker *time.Ticker
var haEgressCheckInterval = time.Second * 5

func setEgressRoutes(egressRoutesInfo []models.EgressNetworkRoutes) {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()
	egressRoutes = egressRoutesInfo
}

func sortRouteMetricByAscending(items []egressPeer) []egressPeer {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Metric == items[j].Metric {
			return items[i].PeerKey < items[j].PeerKey
		}
		return items[i].Metric < items[j].Metric
	})
	return items
}

func getHAEgressDataForProcessing() (data map[string][]egressPeer) {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()
	data = make(map[string][]egressPeer)

	for _, egressRouteI := range egressRoutes {
		// for each egress route, sort it routing node by metric
		for _, egressRangeI := range egressRouteI.EgressRangesWithMetric {
			data[egressRangeI.Network] = append(data[egressRangeI.Network], egressPeer{
				PeerKey:       egressRouteI.PeerKey,
				EgressGwAddr:  egressRouteI.EgressGwAddr,
				EgressGwAddr6: egressRouteI.EgressGwAddr6,
				EgressRange:   egressRangeI.Network,
				Metric:        egressRangeI.RouteMetric,
			})
		}
	}
	for route, peers := range data {
		if len(peers) < 2 {
			delete(data, route)
			continue
		}
		data[route] = sortRouteMetricByAscending(peers)
	}
	return
}

func startEgressHAFailOverThread(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	haEgressTicker = time.NewTicker(time.Second * 5)
	defer haEgressTicker.Stop()
	metricPort := config.GetServer(config.CurrServer).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting startEgressHAFailOverThread")
			return
		case <-haEgressTicker.C:
			nodes := config.GetNodes()
			if len(nodes) == 0 {
				continue
			}
			egressPeerInfo := getHAEgressDataForProcessing()
			if len(egressPeerInfo) == 0 {
				continue
			}
			shouldCheck := false
			for _, egressPeers := range egressPeerInfo {
				if len(egressPeers) > 1 {
					shouldCheck = true
				}
			}
			if !shouldCheck {
				continue
			}
			devicePeerMap, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
			if err != nil {
				slog.Debug("failed to get peers from device: ", "error", err)
				continue
			}
			for egressRange, egressRoutingInfo := range egressPeerInfo {

				_, ipnet, cidrErr := net.ParseCIDR(egressRange)
				if cidrErr != nil {
					continue
				}
				for _, egressRouteI := range egressRoutingInfo {
					devicePeer, ok := devicePeerMap[egressRouteI.PeerKey]
					if !ok {
						continue
					}
					var connected bool
					if egressRouteI.EgressGwAddr.IP != nil {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr.IP.String(), metricPort, 2)
					} else {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr6.IP.String(), metricPort, 2)

					}
					if connected {
						// peer is connected,so continue
						exists := false
						for _, allowedIP := range devicePeer.AllowedIPs {
							if allowedIP.String() == ipnet.String() {
								exists = true
								break
							}
						}
						if !exists {
							devicePeer.AllowedIPs = append(devicePeer.AllowedIPs, *ipnet)
							wireguard.UpdatePeer(&wgtypes.PeerConfig{
								PublicKey:         devicePeer.PublicKey,
								AllowedIPs:        devicePeer.AllowedIPs,
								ReplaceAllowedIPs: true,
								UpdateOnly:        true,
							})
						}
						break
					}
				}
			}

		}
	}
}
