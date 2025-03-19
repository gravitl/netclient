package functions

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
			fmt.Println("\n=======> EGRESS FAILVOER START================>\n ")
			nodes := config.GetNodes()
			if len(nodes) == 0 {
				continue
			}
			egressPeerInfo := getHAEgressDataForProcessing()
			fmt.Printf("Egress Peers Info:  %+v\n", egressPeerInfo)
			if len(egressPeerInfo) == 0 {
				continue
			}
			devicePeerMap, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
			if err != nil {
				slog.Debug("failed to get peers from device: ", "error", err)
				continue
			}
			for egressRange, egressRoutingInfo := range egressPeerInfo {

				// if peer.IsExtClient {
				// 	continue
				// }
				// check connectivity to egress gws
				isEgressGwRangeReachable := false
				allGwsUnReachable := true
				for _, egressRouteI := range egressRoutingInfo {
					//fmt.Printf("======> CHECKING FOR EGRESS RANGE ROUTEI: %+v\n", egressRouteI)
					devicePeer, ok := devicePeerMap[egressRouteI.PeerKey]
					if !ok {
						continue
					}
					//fmt.Printf("======> 2 CHECKING FOR EGRESS RANGE ROUTEI: %+v\n", egressRouteI)
					var connected bool
					if egressRouteI.EgressGwAddr.IP != nil {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr.IP.String(), metricPort, 2)
					} else {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr6.IP.String(), metricPort, 2)

					}
					if connected {
						allGwsUnReachable = false
						// check if egress range is on curr gw peer
						_, ipnet, cidrErr := net.ParseCIDR(egressRange)
						if cidrErr == nil {
							for _, allowedIP := range devicePeer.AllowedIPs {
								if allowedIP.String() == ipnet.String() {
									isEgressGwRangeReachable = true
									break
								}
							}
						}

					}

				}
				if isEgressGwRangeReachable {
					continue
				}
				if allGwsUnReachable {
					continue
				}
				fmt.Println("======> CHECKING FOR EGRESS RANGE: ", egressRange)
				for i, egressRouteI := range egressRoutingInfo {
					fmt.Printf("======> CHECKING FOR EGRESS RANGE ROUTEI: %+v\n", egressRouteI)
					_, ok := devicePeerMap[egressRouteI.PeerKey]
					if !ok {
						continue
					}
					fmt.Printf("======> 2 CHECKING FOR EGRESS RANGE ROUTEI: %+v\n", egressRouteI)
					var connected bool
					if egressRouteI.EgressGwAddr.IP != nil {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr.IP.String(), metricPort, 2)
					} else {
						connected, _ = metrics.PeerConnStatus(egressRouteI.EgressGwAddr6.IP.String(), metricPort, 2)

					}
					fmt.Printf("======> 3 CHECKING FOR EGRESS RANGE ROUTEI: %+v, Conected: %v, Index: %d \n", egressRouteI, connected, i)
					if connected {
						// peer is connected,so continue
						break
					} else {
						if i == len(egressRoutingInfo)-1 {
							break
						}
						// set the route to next peer available
						egressFailOverRoute := egressRoutingInfo[i+1]
						var connected bool
						if egressRouteI.EgressGwAddr.IP != nil {
							connected, _ = metrics.PeerConnStatus(egressFailOverRoute.EgressGwAddr.IP.String(), metricPort, 2)
						} else {
							connected, _ = metrics.PeerConnStatus(egressFailOverRoute.EgressGwAddr6.IP.String(), metricPort, 2)

						}
						if !connected {
							continue
						}
						failOverPeer, ok := devicePeerMap[egressFailOverRoute.PeerKey]
						if !ok {
							continue
						}
						fmt.Printf("======> 4 SETTING FAILOVER EGRESS RANGE ROUTEI: %+v, DevicePeer: %+v \n",
							egressFailOverRoute, failOverPeer)
						_, ipnet, cidrErr := net.ParseCIDR(egressRange)
						if cidrErr == nil {
							failOverPeer.AllowedIPs = append(failOverPeer.AllowedIPs, *ipnet)
							wireguard.UpdatePeer(&wgtypes.PeerConfig{
								PublicKey:         failOverPeer.PublicKey,
								AllowedIPs:        failOverPeer.AllowedIPs,
								ReplaceAllowedIPs: true,
								UpdateOnly:        true,
							})
						}

					}

				}

			}
			fmt.Println("\n=======> EGRESS FAILOVER END================> \n")

		}
	}
}
