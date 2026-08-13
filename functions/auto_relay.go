package functions

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
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

	"golang.org/x/exp/slog"
)

const (
	autoRelayMECacheTTL            = 90 * time.Second
	networkMetricsCacheTTL         = 5 * time.Minute
	autoRelayHealthCheckInterval   = 60 * time.Second
	minPeerConnectionCheckInterval = 30 * time.Second
	signalThrottleMaxAttempts      = 3
	signalThrottleBackoff          = 5 * time.Minute
	relayLivenessProbeCount        = 1
	autoRelayCacheEntryTTL         = 10 * time.Minute
)

type reachabilityState struct {
	reachable bool
	updatedAt time.Time
}

type signalThrottleEntry struct {
	count        int
	lastAttempt  time.Time
	backoffUntil time.Time
}

var (
	autoRelayCacheMutex     = &sync.Mutex{}
	currentNodesCache       = make(map[string]models.Node)
	autoRelayCache          = make(map[schema.NetworkID][]models.Node)
	gwNodesCache            = make(map[schema.NetworkID][]models.Node)
	networkMetricsCache     = make(map[schema.NetworkID]map[string]int64)
	networkMetricsFetchedAt = make(map[schema.NetworkID]time.Time)
	autoRelayConnTicker     *time.Ticker
	signalThrottleCache     = sync.Map{}
	autoRelayMERecentCache  = sync.Map{} // key nodeID|peerNodeID|relayID -> time.Time
	relayReachabilityCache  = make(map[string]reachabilityState)
	gwReachabilityCache     = make(map[string]reachabilityState)
	nodeHealthCheckLastRun  = make(map[string]time.Time)
	peerWatchRunning        atomic.Bool
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

func networkMetricsFresh(network schema.NetworkID) bool {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	fetchedAt, ok := networkMetricsFetchedAt[network]
	return ok && time.Since(fetchedAt) < networkMetricsCacheTTL
}

// getNetworkMetricsWithTTL returns cached relay metrics, refreshing only when empty or past TTL.
func getNetworkMetricsWithTTL(network schema.NetworkID, metricPort int) map[string]int64 {
	if m := getNetworkMetrics(network); len(m) > 0 && networkMetricsFresh(network) {
		return m
	}
	return refreshNetworkMetrics(network, metricPort)
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
	networkMetricsFetchedAt[network] = time.Now()

	return metrics
}

func autoRelaySetKey(nodes []models.Node) string {
	if len(nodes) == 0 {
		return ""
	}
	ids := make([]string, len(nodes))
	for i := range nodes {
		ids[i] = nodes[i].ID.String()
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func setAutoRelayNodes(autoRelaynodes map[schema.NetworkID][]models.Node, gwNodes map[schema.NetworkID][]models.Node, currNodes []models.Node) {
	server := config.GetServer(config.CurrServer)
	metricPort := 51821
	if server != nil && server.MetricsPort != 0 {
		metricPort = server.MetricsPort
	}

	type pendingProbe struct {
		network schema.NetworkID
		nodes   []models.Node
	}
	var toProbe []pendingProbe

	autoRelayCacheMutex.Lock()
	for networkID, nodes := range autoRelaynodes {
		if autoRelaySetKey(autoRelayCache[networkID]) != autoRelaySetKey(nodes) {
			copied := make([]models.Node, len(nodes))
			copy(copied, nodes)
			toProbe = append(toProbe, pendingProbe{network: networkID, nodes: copied})
		}
	}
	for networkID := range autoRelayCache {
		if _, ok := autoRelaynodes[networkID]; !ok {
			delete(networkMetricsCache, networkID)
			delete(networkMetricsFetchedAt, networkID)
		}
	}
	autoRelayCache = autoRelaynodes
	gwNodesCache = gwNodes
	currentNodesCache = make(map[string]models.Node)
	for _, currNode := range currNodes {
		currentNodesCache[currNode.ID.String()] = currNode
	}
	autoRelayCacheMutex.Unlock()

	if server == nil {
		return
	}
	now := time.Now()
	for _, p := range toProbe {
		if len(p.nodes) == 0 {
			autoRelayCacheMutex.Lock()
			delete(networkMetricsCache, p.network)
			delete(networkMetricsFetchedAt, p.network)
			autoRelayCacheMutex.Unlock()
			continue
		}
		m := findNodeLatencies(p.nodes, metricPort)
		autoRelayCacheMutex.Lock()
		networkMetricsCache[p.network] = m
		networkMetricsFetchedAt[p.network] = now
		autoRelayCacheMutex.Unlock()
	}
}

// jitteredPeerCheckInterval returns the peer-connection check interval with ±20% jitter
// so a fleet of NAT hosts does not hit the server on the same tick.
func jitteredPeerCheckInterval() time.Duration {
	applyMinPeerCheckInterval()
	base := networking.PeerConnectionCheckInterval
	if base <= 0 {
		base = minPeerConnectionCheckInterval
	}
	span := int64(base) * 2 / 5 // 40% total range → ±20%
	if span <= 0 {
		return base
	}
	offset := rand.Int64N(span+1) - span/2
	interval := base + time.Duration(offset)
	if interval < minPeerConnectionCheckInterval {
		return minPeerConnectionCheckInterval
	}
	return interval
}

func evictStaleAutoRelayCaches() {
	cutoff := time.Now().Add(-autoRelayCacheEntryTTL)
	now := time.Now()
	autoRelayMERecentCache.Range(func(k, v any) bool {
		if t, ok := v.(time.Time); ok && t.Before(cutoff) {
			autoRelayMERecentCache.Delete(k)
		}
		return true
	})
	signalThrottleCache.Range(func(k, v any) bool {
		entry, ok := v.(signalThrottleEntry)
		if !ok {
			signalThrottleCache.Delete(k)
			return true
		}
		if entry.lastAttempt.Before(cutoff) && now.After(entry.backoffUntil) {
			signalThrottleCache.Delete(k)
		}
		return true
	})
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	for k, v := range relayReachabilityCache {
		if v.updatedAt.Before(cutoff) {
			delete(relayReachabilityCache, k)
		}
	}
	for k, v := range gwReachabilityCache {
		if v.updatedAt.Before(cutoff) {
			delete(gwReachabilityCache, k)
		}
	}
	for k, t := range nodeHealthCheckLastRun {
		if t.Before(cutoff) {
			delete(nodeHealthCheckLastRun, k)
		}
	}
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
	networkID := schema.NetworkID(signal.NetworkID)
	autoRelayNodes := getAutoRelayNodes(networkID)
	if len(autoRelayNodes) == 0 {
		return nil
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	autoRelayNodeMetrics := getNetworkMetricsWithTTL(networkID, metricPort)
	if len(autoRelayNodeMetrics) == 0 {
		return errors.New("failed to find nearest relay node: no cached metrics available")
	}

	if !signal.Reply {
		// Responder: exchange metrics only; initiator commits relay after Reply.
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
			return err
		}
		signalThrottleCache.Delete(signal.FromHostID)
		return nil
	}

	signalThrottleCache.Delete(signal.FromHostID)

	// Initiator after peer metrics: pick relay and commit once to the server.
	var nearestNode *models.Node
	var lowestAvg int64 = 1 << 62
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
	if nearestNode == nil {
		var err error
		nearestNode, err = findNearestNode(autoRelayNodes, metricPort)
		if err != nil {
			slog.Error("failed to find nearest relay node", "error", err)
			return err
		}
	}
	slog.Debug("sending relay me request", "fromNodeID", signal.FromNodeID, "relayNodeID", nearestNode.ID.String())
	return autoRelayMEDebounced(http.MethodPost, signal.Server, signal.ToNodeID, signal.FromNodeID, nearestNode.ID.String())
}

func applyMinPeerCheckInterval() {
	if networking.PeerConnectionCheckInterval < minPeerConnectionCheckInterval {
		networking.PeerConnectionCheckInterval = minPeerConnectionCheckInterval
	}
}

func autoRelayMECacheKey(nodeID, peerNodeID, relayID string) string {
	return nodeID + "|" + peerNodeID + "|" + relayID
}

// autoRelayMEDebounced skips duplicate auto_relay_me API calls within TTL.
func autoRelayMEDebounced(method, serverName, nodeID, peerNodeID, relayID string) error {
	key := autoRelayMECacheKey(nodeID, peerNodeID, relayID)
	if v, ok := autoRelayMERecentCache.Load(key); ok {
		if time.Since(v.(time.Time)) < autoRelayMECacheTTL {
			slog.Debug("skipping duplicate auto_relay_me", "key", key)
			return nil
		}
	}
	err := autoRelayME(method, serverName, nodeID, peerNodeID, relayID)
	if err != nil {
		return err
	}
	autoRelayMERecentCache.Store(key, time.Now())
	return nil
}

func shouldThrottlePeerSignal(hostID string) bool {
	now := time.Now()
	if v, ok := signalThrottleCache.Load(hostID); ok {
		entry := v.(signalThrottleEntry)
		if now.Before(entry.backoffUntil) {
			return true
		}
		if entry.count >= signalThrottleMaxAttempts {
			return true
		}
	}
	return false
}

func recordPeerSignalAttempt(hostID string) {
	now := time.Now()
	var entry signalThrottleEntry
	if v, ok := signalThrottleCache.Load(hostID); ok {
		entry = v.(signalThrottleEntry)
		entry.count++
	} else {
		entry.count = 1
	}
	entry.lastAttempt = now
	if entry.count >= signalThrottleMaxAttempts {
		entry.backoffUntil = now.Add(signalThrottleBackoff)
	}
	signalThrottleCache.Store(hostID, entry)
}

func shouldRunNodeHealthCheck(nodeID string) bool {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	last, ok := nodeHealthCheckLastRun[nodeID]
	if ok && time.Since(last) < autoRelayHealthCheckInterval {
		return false
	}
	nodeHealthCheckLastRun[nodeID] = time.Now()
	return true
}

func peerRelayAlreadyActive(node models.Node, peerNodeID string) bool {
	if node.AutoRelayedPeers == nil {
		return false
	}
	relayID, ok := node.AutoRelayedPeers[peerNodeID]
	return ok && relayID != ""
}

func runPeerConnectionWatchTick(ctx context.Context, server *config.Server, metricPort int) {
	evictStaleAutoRelayCaches()
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
		networkID := schema.NetworkID(node.Network)
		autoRelayNodes := getAutoRelayNodes(networkID)
		autoRelayNodeMetrics := getNetworkMetricsWithTTL(networkID, metricPort)
		if len(autoRelayNodeMetrics) == 0 {
			continue
		}
		currNode := getCurrNode(node.ID.String())
		if currNode.ID.String() != "" && shouldRunNodeHealthCheck(currNode.ID.String()) {
			if currNode.AutoAssignGateway {
				checkAssignGw(server, currNode)
			} else if len(autoRelayNodes) > 0 {
				checkAutoRelayCtx(server, currNode, peers, autoRelayNodes)
			}
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
			if currNode.ID.String() != "" && peerRelayAlreadyActive(currNode, peer.ID) {
				continue
			}
			if shouldThrottlePeerSignal(peer.HostID) {
				slog.Debug("throttle cache hit", "address", peer.Address)
				continue
			}
			connected, err := networking.IsPeerConnected(devicePeer)
			if err != nil || connected {
				continue
			}
			connected, _ = metrics.PeerConnStatus(peer.Address, metricPort, relayLivenessProbeCount)
			if connected {
				continue
			}
			s := models.Signal{
				Server:         config.CurrServer,
				FromHostID:     config.Netclient().ID.String(),
				ToHostID:       peer.HostID,
				FromNodeID:     node.ID.String(),
				ToNodeID:       peer.ID,
				FromHostPubKey: config.Netclient().PublicKey.String(),
				ToHostPubKey:   pubKey,
				NetworkID:      peer.Network,
				Action:         models.ConnNegotiation,
			}
			slog.Debug("sending signal for peer", "address", peer.Address)
			s.AutoRelayNodeMetrics = autoRelayNodeMetrics
			s.TimeStamp = time.Now().Unix()
			if err = SignalPeer(s); err != nil {
				slog.Debug("failed to signal peer", "error", err.Error())
			} else {
				recordPeerSignalAttempt(peer.HostID)
			}
		}
	}
}

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	if server.PeerConnectionCheckInterval != "" {
		sec, err := strconv.Atoi(server.PeerConnectionCheckInterval)
		if err == nil && sec > 0 {
			networking.PeerConnectionCheckInterval = time.Duration(sec) * time.Second
		}
	}
	autoRelayConnTicker = time.NewTicker(jitteredPeerCheckInterval())
	defer autoRelayConnTicker.Stop()

	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-autoRelayConnTicker.C:
			if !peerWatchRunning.CompareAndSwap(false, true) {
				slog.Debug("skipping peer connection watch tick; previous run still active")
				continue
			}
			go func() {
				defer peerWatchRunning.Store(false)
				defer func() {
					if r := recover(); r != nil {
						slog.Error("peer connection watch tick panicked", "panic", r)
					}
				}()
				select {
				case <-ctx.Done():
					return
				default:
				}
				runPeerConnectionWatchTick(ctx, server, metricPort)
			}()
		}
	}
}

func isPeerExist(peerKey string) bool {
	_, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	return err == nil
}

func relayReachabilityKey(nodeID, relayID string) string {
	return nodeID + "|" + relayID
}

func setRelayReachability(nodeID, relayID string, reachable bool) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	relayReachabilityCache[relayReachabilityKey(nodeID, relayID)] = reachabilityState{
		reachable: reachable,
		updatedAt: time.Now(),
	}
}

func wasRelayReachable(nodeID, relayID string) (bool, bool) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	v, ok := relayReachabilityCache[relayReachabilityKey(nodeID, relayID)]
	return v.reachable, ok
}

func checkAutoRelayCtx(server *config.Server, node models.Node, peers models.PeerMap, autoRelayNodes []models.Node) {
	if server == nil {
		return
	}
	slog.Debug("checking auto relay context", "nodeID", node.ID.String(), "address", node.PrimaryAddress())
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for autoRelayedPeerID, currentAutoRelayID := range node.AutoRelayedPeers {
		for _, autoRelayNode := range autoRelayNodes {
			if autoRelayNode.ID.String() != currentAutoRelayID {
				continue
			}
			slog.Debug("checking if current relay is active", "address", autoRelayNode.PrimaryAddress())
			connected, _ := metrics.PeerConnStatus(autoRelayNode.PrimaryAddress(), metricPort, relayLivenessProbeCount)
			wasUp, hadState := wasRelayReachable(node.ID.String(), currentAutoRelayID)
			setRelayReachability(node.ID.String(), currentAutoRelayID, connected)
			if connected {
				break
			}
			// Edge-trigger: only act on transition from reachable to unreachable.
			if hadState && !wasUp {
				break
			}
			if hadState && wasUp {
				slog.Warn("current relay not active", "nodeID", node.ID.String(), "relayID", currentAutoRelayID)
				if err := autoRelayMEDebounced(http.MethodPut, server.Server, node.ID.String(), autoRelayedPeerID, ""); err != nil {
					slog.Error("failed to clear auto relay", "error", err)
				}
				if autoRelayedPeer, ok := peers[autoRelayedPeerID]; ok {
					signalThrottleCache.Delete(autoRelayedPeer.HostID)
				}
			}
			break
		}
	}
}

func gwReachabilityKey(nodeID, gwID string) string {
	return nodeID + "|" + gwID
}

func setGwReachability(nodeID, gwID string, reachable bool) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	gwReachabilityCache[gwReachabilityKey(nodeID, gwID)] = reachabilityState{
		reachable: reachable,
		updatedAt: time.Now(),
	}
}

func wasGwReachable(nodeID, gwID string) (bool, bool) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	v, ok := gwReachabilityCache[gwReachabilityKey(nodeID, gwID)]
	return v.reachable, ok
}

func checkAssignGw(server *config.Server, node models.Node) {
	if !node.AutoAssignGateway {
		return
	}
	gwNodes := getGwNodes(schema.NetworkID(node.Network))
	if len(gwNodes) == 0 {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	if node.RelayedBy != "" {
		for _, gwNode := range gwNodes {
			if gwNode.ID.String() != node.RelayedBy {
				continue
			}
			slog.Debug("checking current gw status", "address", gwNode.PrimaryAddress())
			connected, _ := metrics.PeerConnStatus(gwNode.PrimaryAddress(), metricPort, relayLivenessProbeCount)
			wasUp, hadState := wasGwReachable(node.ID.String(), node.RelayedBy)
			setGwReachability(node.ID.String(), node.RelayedBy, connected)
			if connected {
				return
			}
			if hadState && !wasUp {
				return
			}
			if hadState && wasUp {
				slog.Warn("current gw not active", "address", gwNode.PrimaryAddress())
				_ = autoRelayMEDebounced(http.MethodPut, server.Server, node.ID.String(), "", "")
			}
			return
		}
	}
	nearestNode, err := findNearestNode(gwNodes, metricPort)
	if err == nil {
		slog.Debug("found nearest gw", "address", nearestNode.PrimaryAddress())
		if node.RelayedBy != nearestNode.ID.String() {
			_ = autoRelayMEDebounced(http.MethodPut, server.Server, node.ID.String(), "", nearestNode.ID.String())
		}
	} else if node.RelayedBy != "" {
		slog.Warn("sending signal to unrelay current node", "nodeID", node.ID.String())
		_ = autoRelayMEDebounced(http.MethodPut, server.Server, node.ID.String(), "", "")
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
	headers.Set("Authorization", "Bearer "+token)
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
