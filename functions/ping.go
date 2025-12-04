package functions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/models"
)

// PingResult holds the result of a single peer connectivity check
type PingResult struct {
	Network   string `json:"network"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	IsExt     bool   `json:"is_extclient"`
	Connected bool   `json:"connected"`
	LatencyMs int64  `json:"latency_ms"`
}

// PingPeers checks connectivity to peers and displays status and latency.
// If networkFilter is non-empty, only peers in that network are considered.
// If peerFilter is non-empty, only peers whose name, address, or ID match (case-insensitive) are considered.
// packetCount controls how many packets/probes are sent per peer (<=0 uses a sensible default).
func PingPeers(networkFilter, peerFilter string, jsonOutput bool, packetCount int) error {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return fmt.Errorf("server config not found")
	}

	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}

	peerInfo, err := networking.GetPeerInfo()
	if err != nil {
		return fmt.Errorf("failed to fetch peer info from server: %w", err)
	}

	// Collect all peers to ping
	type peerToPing struct {
		network   string
		pubKey    string
		idAndAddr models.IDandAddr
	}

	peersToPing := []peerToPing{}

	// Normalize filters
	peerFilterLower := strings.ToLower(peerFilter)

	for networkID, peerMap := range peerInfo.NetworkPeerIDs {
		netName := string(networkID)
		if networkFilter != "" && netName != networkFilter {
			continue
		}

		for pubKey, idAndAddr := range peerMap {
			if peerFilterLower != "" {
				lowerName := strings.ToLower(idAndAddr.Name)
				lowerAddr := strings.ToLower(idAndAddr.Address)
				lowerID := strings.ToLower(idAndAddr.ID)
				if !strings.Contains(lowerName, peerFilterLower) &&
					!strings.Contains(lowerAddr, peerFilterLower) &&
					!strings.Contains(lowerID, peerFilterLower) &&
					!strings.Contains(strings.ToLower(pubKey), peerFilterLower) {
					continue
				}
			}

			peersToPing = append(peersToPing, peerToPing{
				network:   netName,
				pubKey:    pubKey,
				idAndAddr: idAndAddr,
			})
		}
	}

	if len(peersToPing) == 0 {
		if peerFilter != "" {
			fmt.Println("\nNo peers matched the provided filters")
		} else if networkFilter != "" {
			fmt.Println("\nNo peers found for network", networkFilter)
		} else {
			fmt.Println("\nNo peers found")
		}
		return nil
	}

	// Collect metrics asynchronously for each peer
	results := make([]PingResult, 0, len(peersToPing))
	var resultsMutex sync.Mutex
	var wg sync.WaitGroup

	for _, peer := range peersToPing {
		wg.Add(1)
		go func(p peerToPing) {
			defer wg.Done()

			var connected bool
			var latency int64

			if p.idAndAddr.IsExtClient {
				connected, latency = metrics.ExtPeerConnStatus(p.idAndAddr.Address, packetCount)
			} else {
				connected, latency = metrics.PeerConnStatus(p.idAndAddr.Address, metricPort, packetCount)
			}

			result := PingResult{
				Network:   p.network,
				Name:      p.idAndAddr.Name,
				Address:   p.idAndAddr.Address,
				IsExt:     p.idAndAddr.IsExtClient,
				Connected: connected,
				LatencyMs: latency,
			}

			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()
		}(peer)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if len(results) == 0 {
		if peerFilter != "" {
			fmt.Println("\nNo peers matched the provided filters")
		} else if networkFilter != "" {
			fmt.Println("\nNo peers found for network", networkFilter)
		} else {
			fmt.Println("\nNo peers found")
		}
		return nil
	}

	// Sort results by network then name for stable output
	sort.Slice(results, func(i, j int) bool {
		if results[i].Network == results[j].Network {
			return results[i].Name < results[j].Name
		}
		return results[i].Network < results[j].Network
	})

	if jsonOutput {
		// Group by network for JSON output
		byNetwork := make(map[string][]PingResult)
		for _, r := range results {
			byNetwork[r.Network] = append(byNetwork[r.Network], r)
		}
		out, err := json.MarshalIndent(byNetwork, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal ping results: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	// Human-readable output - group by network and show separate tables
	fmt.Println()
	fmt.Println("Peer connectivity status:")
	fmt.Println()

	// Group results by network
	byNetwork := make(map[string][]PingResult)
	for _, r := range results {
		byNetwork[r.Network] = append(byNetwork[r.Network], r)
	}

	// Sort networks for stable output
	networks := make([]string, 0, len(byNetwork))
	for n := range byNetwork {
		networks = append(networks, n)
	}
	sort.Strings(networks)

	// Headers without NETWORK column since each table is for a specific network
	headers := []string{"NAME", "ADDRESS", "EXT", "CONNECTED", "LATENCY (ms)"}

	// Print a table for each network
	for _, netName := range networks {
		networkResults := byNetwork[netName]
		fmt.Printf("Network: %s\n", netName)

		// Determine column widths for this network's table
		widths := make([]int, len(headers))
		for i, h := range headers {
			widths[i] = len(h)
		}
		for _, r := range networkResults {
			latencyStr := "N/A"
			if r.Connected && r.LatencyMs != 999 {
				latencyStr = fmt.Sprintf("%d", r.LatencyMs)
			}
			row := []string{
				r.Name,
				r.Address,
				fmt.Sprintf("%t", r.IsExt),
				fmt.Sprintf("%t", r.Connected),
				latencyStr,
			}
			for i, col := range row {
				if len(col) > widths[i] {
					widths[i] = len(col)
				}
			}
		}

		printSep := func() {
			fmt.Print("+")
			for i := range widths {
				fmt.Print(strings.Repeat("-", widths[i]+2))
				fmt.Print("+")
			}
			fmt.Println()
		}

		printRow := func(cols []string) {
			fmt.Print("|")
			for i := range widths {
				cell := ""
				if i < len(cols) {
					cell = cols[i]
				}
				fmt.Printf(" %-*s |", widths[i], cell)
			}
			fmt.Println()
		}

		printSep()
		printRow(headers)
		printSep()
		for i, r := range networkResults {
			latencyStr := "N/A"
			if r.Connected && r.LatencyMs != 999 {
				latencyStr = fmt.Sprintf("%d", r.LatencyMs)
			}
			printRow([]string{
				r.Name,
				r.Address,
				fmt.Sprintf("%t", r.IsExt),
				fmt.Sprintf("%t", r.Connected),
				latencyStr,
			})
			// Add row border after each row (except after the last row)
			if i < len(networkResults)-1 {
				printSep()
			}
		}
		printSep()
		fmt.Println()
	}

	return nil
}


