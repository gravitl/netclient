package functions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/gravitl/netmaker/scope"

	"golang.org/x/exp/slog"
)

const (
	// autoRelayHandshakeGrace lets WireGuard attempt direct handshakes after
	// peers are applied before we signal for auto-relay.
	autoRelayHandshakeGrace = 5 * time.Second
)

var (
	autoRelayCacheMutex = &sync.Mutex{}
	currentNodesCache   = make(map[string]models.Node)
	autoRelayCache      = make(map[schema.NetworkID][]models.Node)
	gwNodesCache        = make(map[schema.NetworkID][]models.Node)
	networkMetricsCache = make(map[schema.NetworkID]map[string]int64) // Cached metrics per network
	autoRelayConnTicker *time.Ticker
	signalThrottleCache = sync.Map{}

	autoRelayWatchCtx    atomic.Pointer[context.Context]
	autoRelayScanMu      sync.Mutex
	autoRelayScheduleGen atomic.Uint64
)

func getAutoRelayNodes(network schema.NetworkID) []models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return autoRelayCache[network]
}
func getGwNodes(network schema.NetworkID) []models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return gwNodesCache[network]
}
func getCurrNode(nodeID string) models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return currentNodesCache[nodeID]
}

func getNetworkMetrics(network schema.NetworkID) map[string]int64 {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return networkMetricsCache[network]
}

func refreshNetworkMetrics(network schema.NetworkID, metricPort int) map[string]int64 {
	nodes := getAutoRelayNodes(network)
	if len(nodes) == 0 {
		return map[string]int64{}
	}

	copiedNodes := make([]models.Node, len(nodes))
	copy(copiedNodes, nodes)
	metrics := findNodeLatencies(copiedNodes, metricPort)

	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	networkMetricsCache[network] = metrics

	return metrics
}

func setAutoRelayNodes(autoRelaynodes map[schema.NetworkID][]models.Node, gwNodes map[schema.NetworkID][]models.Node, currNodes []models.Node) {
	autoRelayCacheMutex.Lock()
	autoRelayCache = autoRelaynodes
	gwNodesCache = gwNodes
	currentNodesCache = make(map[string]models.Node)
	for _, currNode := range currNodes {
		currentNodesCache[currNode.ID.String()] = currNode
	}
	// Clear stale metrics; refresh async so peer-update / pull paths are not
	// blocked on relay latency probes (those can take several seconds).
	networkMetricsCache = make(map[schema.NetworkID]map[string]int64)
	autoRelayCacheMutex.Unlock()

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	go func(networks map[schema.NetworkID][]models.Node, port int) {
		for networkID, nodes := range networks {
			if len(nodes) == 0 {
				continue
			}
			_ = refreshNetworkMetrics(networkID, port)
		}
	}(autoRelaynodes, metricPort)
}

// processPeerSignal - processes the peer signals for any updates from peers
func processPeerSignal(signal models.Signal) {
	// process recieved new signal from peer
	// if signal is older than 3s ignore it,wait for a fresh signal from peer
	if time.Now().Unix()-signal.TimeStamp > 5 {
		return
	}
	switch signal.Action {
	case models.ConnNegotiation:
		if !isPeerExist(signal.FromHostPubKey) {
			return
		}
		devicePeer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), signal.FromHostPubKey)
		if err != nil {
			return
		}
		// check if there is handshake on interface
		connected, err := networking.IsPeerConnected(devicePeer)
		if err != nil || connected {
			return
		}
		err = handlePeerRelaySignal(signal)
		if err != nil {
			logger.Log(2, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
		}
	}

}

func handlePeerRelaySignal(signal models.Signal) error {
	slog.Debug("received signal from peer", "pubkey", signal.FromHostPubKey)
	server := config.GetServer(signal.Server)
	if server == nil {
		return errors.New("server config not found")
	}
	autoRelayNodes := getAutoRelayNodes(schema.NetworkID(signal.NetworkID))
	if len(autoRelayNodes) == 0 {
		return nil
	}
	// Use cached metrics from setAutoRelayNodes
	autoRelayNodeMetrics := getNetworkMetrics(schema.NetworkID(signal.NetworkID))
	if len(autoRelayNodeMetrics) == 0 {
		metricPort := server.MetricsPort
		if metricPort == 0 {
			metricPort = 51821
		}
		slog.Debug("no cached relay metrics found; refreshing", "networkID", signal.NetworkID)
		autoRelayNodeMetrics = refreshNetworkMetrics(schema.NetworkID(signal.NetworkID), metricPort)
		if len(autoRelayNodeMetrics) == 0 {
			return errors.New("failed to find nearest relay node: no cached metrics available")
		}
	}
	if !signal.Reply {
		// signal back
		s := models.Signal{
			Server:               signal.Server,
			FromHostID:           signal.ToHostID,
			FromNodeID:           signal.ToNodeID,
			FromHostPubKey:       signal.ToHostPubKey,
			ToHostPubKey:         signal.FromHostPubKey,
			ToHostID:             signal.FromHostID,
			ToNodeID:             signal.FromNodeID,
			Reply:                true,
			NetworkID:            signal.NetworkID,
			Action:               models.ConnNegotiation,
			AutoRelayNodeMetrics: autoRelayNodeMetrics,
			TimeStamp:            time.Now().Unix(),
		}
		err := SignalPeer(s)
		if err != nil {
			slog.Warn("failed to signal peer", "error", err.Error())
		} else {
			signalThrottleCache.Delete(signal.FromHostID)
		}
	} else {
		signalThrottleCache.Delete(signal.FromHostID)
	}

	// compare my node autoRelayNodeMetrics with signal.AutoRelayNodeMetrics and choose closest to both of them on average and set nearest node
	var nearestNode *models.Node
	var lowestAvg int64 = 1 << 62 // large
	if len(signal.AutoRelayNodeMetrics) > 0 {
		for i := range autoRelayNodes {
			n := &autoRelayNodes[i]
			myLat, okMy := autoRelayNodeMetrics[n.ID.String()]
			peerLat, okPeer := signal.AutoRelayNodeMetrics[n.ID.String()]
			if okMy && okPeer {
				avg := (myLat + peerLat) / 2
				if avg < lowestAvg {
					lowestAvg = avg
					nearestNode = n
				}
			}
		}
	}
	// Fallback: if no common metrics with peer, use our nearest
	if nearestNode == nil {
		metricPort := server.MetricsPort
		if metricPort == 0 {
			metricPort = 51821
		}
		var err error
		nearestNode, err = findNearestNode(autoRelayNodes, metricPort)
		if err != nil {
			slog.Error("failed to find nearest relay node", "error", err)
			return err
		}
	}
	slog.Debug("sending relay me request", "fromNodeID", signal.FromNodeID, "relayNodeID", nearestNode.ID.String())
	err := autoRelayME(http.MethodPost, signal.Server, signal.ToNodeID, signal.FromNodeID, nearestNode.ID.String())
	if err != nil {
		slog.Error("failed to signal server to relay me", "error", err)
		return err
	}

	return nil
}

// shouldRunScheduledScan reports whether a deferred one-shot is still the latest.
func shouldRunScheduledScan(scheduled, current uint64) bool {
	return scheduled == current
}

// scheduleAutoRelayPeerScan waits for a WireGuard handshake grace, then runs
// one bad-peer → signal pass. Rapid peer updates coalesce to the latest schedule.
// No-op until watchPeerConnections is running (Pro only).
func scheduleAutoRelayPeerScan() {
	p := autoRelayWatchCtx.Load()
	if p == nil {
		return
	}
	ctx := *p
	gen := autoRelayScheduleGen.Add(1)
	go func(gen uint64) {
		timer := time.NewTimer(autoRelayHandshakeGrace)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if !shouldRunScheduledScan(gen, autoRelayScheduleGen.Load()) {
			return
		}
		slog.Debug("auto-relay: running post-peer handshake scan")
		runAutoRelayPeerScan(ctx)
	}(gen)
}

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	autoRelayWatchCtx.Store(&ctx)
	defer autoRelayWatchCtx.Store(nil)

	if server.PeerConnectionCheckInterval != "" {
		sec, err := strconv.Atoi(server.PeerConnectionCheckInterval)
		if err == nil && sec > 0 {
			networking.PeerConnectionCheckInterval = time.Duration(sec) * time.Second
		}
	}
	autoRelayConnTicker = time.NewTicker(networking.PeerConnectionCheckInterval)
	defer autoRelayConnTicker.Stop()

	// Peers from the initial host pull are already applied — scan once after grace
	// instead of waiting a full ticker interval.
	scheduleAutoRelayPeerScan()

	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-autoRelayConnTicker.C:
			go runAutoRelayPeerScan(ctx)
		}
	}
}

// runAutoRelayPeerScan signals peers that lack a WireGuard handshake / metrics
// path so they can negotiate auto-relay. Serialized so ticker and one-shot scans
// do not pile up.
func runAutoRelayPeerScan(ctx context.Context) {
	autoRelayScanMu.Lock()
	defer autoRelayScanMu.Unlock()

	select {
	case <-ctx.Done():
		return
	default:
	}

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}

	nodes := config.GetNodes()
	if len(nodes) == 0 {
		return
	}
	peerInfo, err := networking.GetPeerInfo()
	if err != nil {
		slog.Error("failed to get peer info", "error", err)
		return
	}
	devicePeerMap, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		slog.Debug("failed to get peers from device: ", "error", err)
		return
	}
	for _, node := range nodes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if node.Server != config.CurrServer {
			continue
		}
		peers, ok := peerInfo.NetworkPeerIDs[schema.NetworkID(node.Network)]
		if !ok {
			continue
		}
		autoRelayNodes := getAutoRelayNodes(schema.NetworkID(node.Network))
		networkID := schema.NetworkID(node.Network)
		currNode := getCurrNode(node.ID.String())
		hasCurrNode := currNode.ID.String() != ""

		if hasCurrNode && currNode.AutoAssignGateway {
			checkAssignGw(server, currNode)
		}

		autoRelayNodeMetrics := getNetworkMetrics(networkID)
		if len(autoRelayNodeMetrics) == 0 {
			autoRelayNodeMetrics = refreshNetworkMetrics(networkID, metricPort)
			if len(autoRelayNodeMetrics) == 0 {
				continue
			}
		}
		if hasCurrNode && !currNode.AutoAssignGateway && len(autoRelayNodes) > 0 {
			checkAutoRelayCtx(server, currNode, peers, autoRelayNodes)
		}
		for pubKey, peer := range peers {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if peer.IsExtClient {
				continue
			}
			devicePeer, ok := devicePeerMap[pubKey]
			if !ok {
				continue
			}
			if cnt, ok := signalThrottleCache.Load(peer.HostID); ok && cnt.(int) > 3 {
				slog.Debug("throttle cache hit", "address", peer.Address)
				continue
			}
			connected, err := networking.IsPeerConnected(devicePeer)
			if err != nil || connected {
				continue
			}
			// Overlay metrics need a tunnel. With no handshake yet the probe
			// always fails and costs seconds (2× timeout) per peer — skip it.
			if !devicePeer.LastHandshakeTime.IsZero() {
				connected, _ = metrics.PeerConnStatus(peer.Address, metricPort, 2)
				if connected {
					continue
				}
			}
			if len(autoRelayNodeMetrics) == 0 {
				continue
			}
			if config.GetServer(config.CurrServer) == nil {
				continue
			}
			s := models.Signal{
				Server:               config.CurrServer,
				FromHostID:           config.Netclient().ID.String(),
				ToHostID:             peer.HostID,
				FromNodeID:           node.ID.String(),
				ToNodeID:             peer.ID,
				FromHostPubKey:       config.Netclient().PublicKey.String(),
				ToHostPubKey:         pubKey,
				NetworkID:            peer.Network,
				Action:               models.ConnNegotiation,
				AutoRelayNodeMetrics: autoRelayNodeMetrics,
				TimeStamp:            time.Now().Unix(),
			}
			slog.Debug("sending signal for peer", "address", peer.Address)
			err = SignalPeer(s)
			if err != nil {
				slog.Debug("failed to signal peer", "error", err.Error())
				continue
			}
			if cnt, ok := signalThrottleCache.Load(peer.HostID); ok {
				if cnt.(int) <= 3 {
					signalThrottleCache.Store(peer.HostID, cnt.(int)+1)
				}
			} else {
				signalThrottleCache.Store(peer.HostID, 1)
			}
		}
	}
}

func isPeerExist(peerKey string) bool {
	_, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	return err == nil
}

func checkAutoRelayCtx(server *config.Server, node models.Node, peers models.PeerMap, autoRelayNodes []models.Node) {
	if server == nil {
		return
	}
	slog.Debug("checking auto relay context", "nodeID", node.ID.String(), "address", node.PrimaryAddress())
	// group the auto relayed peers by the relay in use, so each relay is
	// checked once instead of once per peer
	relayedPeers := make(map[string][]string)
	for autoRelayedPeerID, currentAutoRelayID := range node.AutoRelayedPeers {
		relayedPeers[currentAutoRelayID] = append(relayedPeers[currentAutoRelayID], autoRelayedPeerID)
	}
	for _, autoRelayNode := range autoRelayNodes {
		relayID := autoRelayNode.ID.String()
		peerIDs, ok := relayedPeers[relayID]
		if !ok {
			continue
		}
		slog.Debug("checking if current relay is active", "address", autoRelayNode.PrimaryAddress())
		connected, _ := metrics.PeerConnStatus(autoRelayNode.PrimaryAddress(), server.MetricsPort, 4)
		if connected {
			continue
		}
		slog.Warn("current relay not active", "nodeID", node.ID.String(), "relayID", relayID)
		for _, autoRelayedPeerID := range peerIDs {
			err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), autoRelayedPeerID, "")
			if err != nil {
				slog.Error("failed to switch to nearest gw node", "error", err)
			}
			if autoRelayedPeer, ok := peers[autoRelayedPeerID]; ok {
				signalThrottleCache.Delete(autoRelayedPeer.HostID)
			}
		}
	}
}

func checkAssignGw(server *config.Server, node models.Node) {
	if !node.AutoAssignGateway {
		return
	}
	gwNodes := getGwNodes(schema.NetworkID(node.Network))
	if len(gwNodes) == 0 {
		return
	}
	// check if current gw is reachable
	if node.RelayedBy != "" {
		for _, gwNode := range gwNodes {
			if gwNode.ID.String() == node.RelayedBy {
				slog.Debug("checking current gw status", "address", gwNode.PrimaryAddress())
				connected, _ := metrics.PeerConnStatus(gwNode.PrimaryAddress(), server.MetricsPort, 3)
				if !connected {
					slog.Warn("current gw not active", "address", gwNode.PrimaryAddress())
					err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", "")
					if err != nil {
						slog.Error("failed to switch to nearest gw node", "error", err)
					}
				}
				return
			}
		}
	}
	nearestNode, err := findNearestNode(gwNodes, server.MetricsPort)
	if err == nil {
		slog.Debug("found nearest gw", "address", nearestNode.PrimaryAddress())
		if node.RelayedBy != nearestNode.ID.String() {
			err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", nearestNode.ID.String())
			if err != nil {
				slog.Error("failed to switch to nearest gw node", "error", err)
			}
		}
	} else if node.RelayedBy != "" {
		slog.Warn("sending signal to unrelay current node", "nodeID", node.ID.String())
		// current gw is unavailable, unrelay the node
		err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", "")
		if err != nil {
			slog.Error("failed to unrelay node", "error", err)
		}
	}

}

// findNearestNode finds the node with the lowest latency from a list of nodes
// Latency calculations are performed in parallel for better performance
func findNearestNode(nodes []models.Node, metricPort int) (*models.Node, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no relay nodes available")
	}

	var nearestNode *models.Node
	var lowestLatency int64 = 999 // Start with a very high value (milliseconds)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process nodes in parallel
	for i := range nodes {
		node := &nodes[i]
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			// Try to get metrics/ping the node to determine latency
			connected, latency := metrics.PeerConnStatus(n.PrimaryAddress(), metricPort, 2)
			if !connected || latency <= 0 {
				// If we can't reach the node or got invalid latency, skip it
				slog.Debug("relay node unreachable", "node", n.ID.String(), "address", n.PrimaryAddress())
				return
			}

			// Update nearest node if this one has lower latency
			mu.Lock()
			if latency < lowestLatency {
				lowestLatency = latency
				nearestNode = n
				slog.Debug("found reachable relay node", "node", n.ID.String(), "latency_ms", latency)
			}
			mu.Unlock()
		}(node)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// If no node was reachable, return error
	if nearestNode == nil {
		return nil, errors.New("no reachable relay nodes found")
	}

	return nearestNode, nil
}

// findNodeLatencies returns a map of relay nodes with their latency values
// The map key is the node ID (string) and the value is latency in milliseconds
// Latency calculations are performed in parallel for better performance
func findNodeLatencies(nodes []models.Node, metricPort int) map[string]int64 {
	if len(nodes) == 0 {
		return make(map[string]int64)
	}

	nodeLatencies := make(map[string]int64)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process nodes in parallel
	for i := range nodes {
		node := &nodes[i]
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			// Try to get metrics/ping the node to determine latency
			connected, latency := metrics.PeerConnStatus(n.PrimaryAddress(), metricPort, 2)
			if connected && latency > 0 {
				// Only include reachable nodes with valid latency
				mu.Lock()
				nodeLatencies[n.ID.String()] = latency
				mu.Unlock()
				slog.Debug("found reachable relay node", "node", n.ID.String(), "latency_ms", latency)
			} else {
				slog.Debug("relay node unreachable", "node", n.ID.String(), "address", n.PrimaryAddress(), "metricsPort", metricPort)
			}
		}(node)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	return nodeLatencies
}

// autoRelayME - signals the server to auto relay
func autoRelayME(method, serverName, nodeID, peernodeID, relayID string) error {
	server := config.GetServer(serverName)
	if server == nil {
		return errors.New("server config not found")
	}
	host := config.Netclient()
	if host == nil {
		return fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/api/v1/node/%s/auto_relay_me", server.API, nodeID)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	auth.ApplyAPIHeaders(headers, token, host)
	headers.Set(scope.HeaderTenantID, host.TenantID)
	_, err = ncutils.SendRequest(method, url, headers, models.AutoRelayMeReq{NodeID: peernodeID, AutoRelayGwID: relayID})
	if err != nil {
		return err
	}
	return nil
}

// SignalPeer - signals the peer with host's turn relay endpoint
func SignalPeer(signal models.Signal) error {
	return publishPeerSignal(signal)
}
