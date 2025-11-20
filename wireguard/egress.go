package wireguard

import (
	"context"
	"fmt"
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
var EgressResetCh = make(chan struct{}, 2)
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
	egressRoutes = []models.EgressNetworkRoutes{}
	haEgressPeerCache = make(map[string][]net.IPNet)
	egressRoutesCacheMutex.Unlock()

	egressDomainCacheMutex.Lock()
	egressDomainCache = []models.EgressDomain{}
	egressDomainCacheMutex.Unlock()
}

func sortRouteMetricByAscending(items []egressPeer, metricsPort int) []egressPeer {
	if metricsPort == 0 {
		metricsPort = 51821
	}

	// Pre-fetch all latencies concurrently to avoid network calls during sort comparisons
	latencyCache := make(map[string]int64)
	var latencyCacheMutex sync.Mutex
	var wg sync.WaitGroup

	// Collect unique peers to check
	uniquePeers := make(map[string]egressPeer)
	for _, item := range items {
		if _, exists := uniquePeers[item.PeerKey]; !exists {
			uniquePeers[item.PeerKey] = item
		}
	}

	// Check latencies in parallel
	for peerKey, item := range uniquePeers {
		wg.Add(1)
		go func(key string, peer egressPeer) {
			defer wg.Done()
			var latency int64
			if peer.EgressGwAddr.IP != nil {
				_, latency = metrics.PeerConnStatus(peer.EgressGwAddr.IP.String(), metricsPort, 1)
			} else if peer.EgressGwAddr6.IP != nil {
				_, latency = metrics.PeerConnStatus(peer.EgressGwAddr6.IP.String(), metricsPort, 2)
			}
			latencyCacheMutex.Lock()
			latencyCache[key] = latency
			latencyCacheMutex.Unlock()
		}(peerKey, item)
	}
	wg.Wait()

	sort.Slice(items, func(i, j int) bool {
		if items[i].Metric == items[j].Metric {
			// sort by latency using cached values
			latencyI, hasI := latencyCache[items[i].PeerKey]
			latencyJ, hasJ := latencyCache[items[j].PeerKey]

			if hasI && hasJ {
				if latencyI != latencyJ {
					return latencyI < latencyJ
				}
			}
			return items[i].PeerKey < items[j].PeerKey
		}
		return items[i].Metric < items[j].Metric
	})
	return items
}

func getHAEgressDataForProcessing(metricsPort int) (data map[string][]egressPeer) {
	// Only hold lock while copying data from shared cache
	egressRoutesCacheMutex.Lock()
	egressRoutesCopy := make([]models.EgressNetworkRoutes, len(egressRoutes))
	copy(egressRoutesCopy, egressRoutes)
	egressRoutesCacheMutex.Unlock()

	data = make(map[string][]egressPeer)

	for _, egressRouteI := range egressRoutesCopy {
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

	// Perform expensive sorting and network calls without holding the mutex
	for route, peers := range data {
		if len(peers) < 2 {
			delete(data, route)
			continue
		}
		data[route] = sortRouteMetricByAscending(peers, metricsPort)
	}
	return
}

func StartEgressHAFailOverThread(ctx context.Context, waitg *sync.WaitGroup) {
	defer fmt.Println("=======> EXITING StartEgressHAFailOverThread")
	defer waitg.Done()
	HaEgressTicker = time.NewTicker(HaEgressCheckInterval)
	defer HaEgressTicker.Stop()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	nodes := config.GetNodes()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("REV CTX DONE SIGNAL exiting startEgressHAFailOverThread")
			resetHAEgressCache()
			return
		case <-EgressResetCh:
			nodes = config.GetNodes()
		case <-HaEgressTicker.C:
			if len(nodes) == 0 {
				continue
			}

			// Check context before expensive operation
			select {
			case <-ctx.Done():
				return
			default:
			}

			egressPeerInfo := getHAEgressDataForProcessing(metricPort)
			if len(egressPeerInfo) == 0 {
				continue
			}

			// Check context again after potentially slow operation
			select {
			case <-ctx.Done():
				return
			default:
			}

			//fmt.Printf("HA Egress Ticker: %+v\n", egressPeerInfo)
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
				// Check context at start of goroutine
				select {
				case <-ctx.Done():
					return
				default:
				}
				go func(egressRange string, egressRoutingInfo []egressPeer) {
					// Check context at start of goroutine
					select {
					case <-ctx.Done():
						return
					default:
					}
					_, ipnet, cidrErr := net.ParseCIDR(egressRange)
					if cidrErr != nil {
						return
					}
					var haActiveRoutingPeer string
					for _, egressRouteI := range egressRoutingInfo {
						// Check context before network calls
						select {
						case <-ctx.Done():
							return
						default:
						}

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
						// Check context before cleanup operations
						select {
						case <-ctx.Done():
							return
						default:
						}

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

func checkIfEgressHAPeer(peer *wgtypes.PeerConfig, haEgressData map[string][]egressPeer) bool {
	egressRoutesCacheMutex.Lock()
	defer egressRoutesCacheMutex.Unlock()

	egressList, ok := haEgressPeerCache[peer.PublicKey.String()]
	if !ok {
		return false
	}
	//fmt.Printf("===> Found HA Egress Peer: %s, Data: %+v\n", peer.PublicKey.String(), data)
	// check if peer exists
	exists := false
	for _, egressPeers := range haEgressData {
		for _, egressPeerI := range egressPeers {
			if egressPeerI.PeerKey == peer.PublicKey.String() {
				exists = true
				break
			}
		}
		if exists {
			break
		}
	}
	if !exists {
		delete(haEgressPeerCache, peer.PublicKey.String())
		return false
	}
	peer.AllowedIPs = append(peer.AllowedIPs, egressList...)
	peer.AllowedIPs = logic.UniqueIPNetList(peer.AllowedIPs)

	return true
}
