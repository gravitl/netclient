package wireguard

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"

	"github.com/gravitl/netmaker/logic"
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
var HaEgressTicker *time.Ticker
var HaEgressCheckInterval = time.Second * 2
var haEgressPeerCache = make(map[string][]net.IPNet)
var egressDomainCache = []models.EgressDomain{}
var egressDomainAnswers = make(map[string][]string)
var egressDomainCacheMutex = &sync.Mutex{}

func SetEgressDomains(egressDomains []models.EgressDomain) {
	egressDomainCacheMutex.Lock()
	defer egressDomainCacheMutex.Unlock()
	egressDomainCache = egressDomains
}

func GetEgressDomains() []models.EgressDomain {
	egressDomainCacheMutex.Lock()
	defer egressDomainCacheMutex.Unlock()
	return egressDomainCache
}

func SetDomainAnsInCache(egressDomain models.EgressDomain, ips []string) {
	egressDomainCacheMutex.Lock()
	defer egressDomainCacheMutex.Unlock()
	egressDomainAnswers[egressDomain.ID] = ips
}

func GetDomainAnsFromCache(egressDomain models.EgressDomain) (ips []string) {
	egressDomainCacheMutex.Lock()
	defer egressDomainCacheMutex.Unlock()
	return egressDomainAnswers[egressDomain.ID]
}

func SetEgressRoutesInCache(egressRoutesInfo []models.EgressNetworkRoutes) {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()
	egressRoutes = egressRoutesInfo
}

func resetHAEgressCache() {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()
	egressRoutes = []models.EgressNetworkRoutes{}
	haEgressPeerCache = make(map[string][]net.IPNet)
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

func StartEgressHAFailOverThread(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	HaEgressTicker = time.NewTicker(HaEgressCheckInterval)
	defer HaEgressTicker.Stop()
	metricPort := config.GetServer(config.CurrServer).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting startEgressHAFailOverThread")
			resetHAEgressCache()
			return
		case <-HaEgressTicker.C:
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
			devicePeerMap, err := GetPeersFromDevice(ncutils.GetInterfaceName())
			if err != nil {
				slog.Debug("failed to get peers from device: ", "error", err)
				continue
			}

			for egressRange, egressRoutingInfo := range egressPeerInfo {
				go func(egressRange string, egressRoutingInfo []egressPeer) {
					_, ipnet, cidrErr := net.ParseCIDR(egressRange)
					if cidrErr != nil {
						return
					}
					var haActiveRoutingPeer string
					for _, egressRouteI := range egressRoutingInfo {
						devicePeer, ok := devicePeerMap[egressRouteI.PeerKey]
						if !ok {
							continue
						}
						var connected bool
						if egressRouteI.EgressGwAddr.IP != nil {
							// trigger a handshake
							//connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr.IP.String(), metricPort, 1)
							//if !connected {
							connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr.IP.String(), metricPort, 1)
							//}
						} else if egressRouteI.EgressGwAddr6.IP != nil {
							connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr6.IP.String(), metricPort, 2)
						}
						if connected {
							// peer is connected,so continue
							exists := false
							for _, allowedIP := range devicePeer.AllowedIPs {
								if allowedIP.String() == ipnet.String() {
									exists = true
									egressRoutesCacheMutex.Lock()
									haEgressPeerCache[devicePeer.PublicKey.String()] = devicePeer.AllowedIPs
									egressRoutesCacheMutex.Unlock()
									break
								}
							}
							if !exists {
								peer, err := GetPeer(ncutils.GetInterfaceName(), devicePeer.PublicKey.String())
								if err == nil {
									peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
									peer.AllowedIPs = logic.UniqueIPNetList(peer.AllowedIPs)
									UpdatePeer(&wgtypes.PeerConfig{
										PublicKey:         peer.PublicKey,
										AllowedIPs:        peer.AllowedIPs,
										ReplaceAllowedIPs: false,
										UpdateOnly:        true,
									})
									egressRoutesCacheMutex.Lock()
									haEgressPeerCache[peer.PublicKey.String()] = peer.AllowedIPs
									egressRoutesCacheMutex.Unlock()
								}

							}
							haActiveRoutingPeer = devicePeer.PublicKey.String()
							break
						}
					}
					// remove other peers in ha cache
					for _, egressRouteI := range egressRoutingInfo {
						if egressRouteI.PeerKey != haActiveRoutingPeer {
							peer, err := GetPeer(ncutils.GetInterfaceName(), egressRouteI.PeerKey)
							if err == nil {
								UpdatePeer(&wgtypes.PeerConfig{
									PublicKey:         peer.PublicKey,
									AllowedIPs:        removeIP(peer.AllowedIPs, *ipnet),
									ReplaceAllowedIPs: false,
									UpdateOnly:        true,
								})
							}
							egressRoutesCacheMutex.Lock()
							delete(haEgressPeerCache, egressRouteI.PeerKey)
							egressRoutesCacheMutex.Unlock()
						}
					}
				}(egressRange, egressRoutingInfo)

			}

		}
	}
}

func removeIP(slice []net.IPNet, item net.IPNet) []net.IPNet {
	result := make([]net.IPNet, 0, len(slice))
	for _, v := range slice {
		if v.String() != item.String() {
			result = append(result, v)
		}
	}
	return result
}

func checkIfEgressHAPeer(peer *wgtypes.PeerConfig) bool {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()
	egressList, ok := haEgressPeerCache[peer.PublicKey.String()]
	if ok {
		peer.AllowedIPs = append(peer.AllowedIPs, egressList...)
		peer.AllowedIPs = logic.UniqueIPNetList(peer.AllowedIPs)
	}
	return ok
}
