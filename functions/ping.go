package functions

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/text/width"
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

// displayWidth calculates the display width of a string using golang.org/x/text/width
// This properly handles emojis, wide characters, and other Unicode complexities
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch width.LookupRune(r).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			w += 2
		case width.EastAsianNarrow, width.EastAsianHalfwidth, width.Neutral:
			w += 1
		default:
			// For emojis and other symbols, check if they're typically wide
			if (r >= 0x1F300 && r <= 0x1F9FF) || // Emojis
			   (r >= 0x1F600 && r <= 0x1F64F) ||
			   (r >= 0x2600 && r <= 0x26FF) ||
			   (r >= 0x2700 && r <= 0x27BF) {
				w += 2 // Emojis typically take 2 columns
			} else {
				w += 1
			}
		}
	}
	return w
}

// padRight pads a string to the specified display width, adding spaces on the right
func padRight(s string, width int) string {
	currentWidth := displayWidth(s)
	if currentWidth >= width {
		return s
	}
	// Add the exact number of spaces needed
	spacesNeeded := width - currentWidth
	return s + strings.Repeat(" ", spacesNeeded)
}

// PingPeers checks connectivity to peers and displays status and latency.
// If networkFilter is non-empty, only peers in that network are considered.
// If peerFilter is non-empty, only peers whose name, address, or ID match (case-insensitive) are considered.
// packetCount controls how many packets/probes are sent per peer (<=0 uses a sensible default).
// ipVersion can be "4" for IPv4, "6" for IPv6, or "" for default address.
func PingPeers(networkFilter, peerFilter string, jsonOutput bool, packetCount int, ipVersion string) error {
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

			// Helper function to check if an address is valid (not empty, not "<nil>", and parseable as IP)
			isValidAddress := func(addr string) bool {
				if addr == "" || addr == "<nil>" {
					return false
				}
				// Try to parse as IP to validate
				ip := net.ParseIP(addr)
				return ip != nil
			}

			// Select address based on IP version flag
			var addressToUse string
			var addressToDisplay string
			switch ipVersion {
			case "4":
				// Use IPv4 address, fallback to default Address if Address4 is empty or invalid
				if isValidAddress(p.idAndAddr.Address4) {
					addressToUse = p.idAndAddr.Address4
					addressToDisplay = p.idAndAddr.Address4
				} else if isValidAddress(p.idAndAddr.Address) {
					addressToUse = p.idAndAddr.Address
					addressToDisplay = p.idAndAddr.Address
				} else {
					// No valid address available
					return
				}
			case "6":
				// Use IPv6 address, fallback to default Address if Address6 is empty or invalid
				if isValidAddress(p.idAndAddr.Address6) {
					addressToUse = p.idAndAddr.Address6
					addressToDisplay = p.idAndAddr.Address6
				} else if isValidAddress(p.idAndAddr.Address) {
					addressToUse = p.idAndAddr.Address
					addressToDisplay = p.idAndAddr.Address
				} else {
					// No valid address available
					return
				}
			default:
				// Use default Address field
				if isValidAddress(p.idAndAddr.Address) {
					addressToUse = p.idAndAddr.Address
					addressToDisplay = p.idAndAddr.Address
				} else {
					// No valid address available
					return
				}
			}

			var connected bool
			var latency int64

			if p.idAndAddr.IsExtClient {
				connected, latency = metrics.ExtPeerConnStatus(addressToUse, packetCount)
			} else {
				connected, latency = metrics.PeerConnStatus(addressToUse, metricPort, packetCount)
			}

			result := PingResult{
				Network:   p.network,
				Name:      p.idAndAddr.Name,
				Address:   addressToDisplay,
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
	headers := []string{"NAME", "ADDRESS", "CONNECTED", "LATENCY (ms)"}

	// Print a table for each network
	for _, netName := range networks {
		networkResults := byNetwork[netName]
		fmt.Printf("Network: %s\n", netName)

		// Determine column widths for this network's table
		widths := make([]int, len(headers))
		for i, h := range headers {
			widths[i] = displayWidth(h)
		}
		for _, r := range networkResults {
			// Format name with emoji prefix: 📄 for external clients, 💻 for regular devices
			var nameStr string
			if r.IsExt {
				nameStr = "📄 " + r.Name
			} else {
				nameStr = "💻 " + r.Name
			}
			
			latencyStr := "N/A"
			if r.Connected && r.LatencyMs != 999 {
				latencyStr = fmt.Sprintf("%d", r.LatencyMs)
			}
			row := []string{
				nameStr,
				r.Address,
				fmt.Sprintf("%t", r.Connected),
				latencyStr,
			}
			for i, col := range row {
				colWidth := displayWidth(col)
				if colWidth > widths[i] {
					widths[i] = colWidth
				}
			}
		}

		printSep := func() {
			fmt.Print("+")
			for i := range widths {
				// Separator width = content width + 2 spaces (one on each side)
				sepWidth := widths[i] + 2
				fmt.Print(strings.Repeat("-", sepWidth))
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
				// Pad cell to match the column display width
				padded := padRight(cell, widths[i])
				// Print: space + padded content + space + pipe
				fmt.Print(" ")
				fmt.Print(padded)
				fmt.Print(" ")
				fmt.Print("|")
			}
			fmt.Println()
		}

		printSep()
		printRow(headers)
		printSep()
		for i, r := range networkResults {
			// Format name with emoji prefix: 📄 for external clients, 💻 for regular devices
			var nameStr string
			if r.IsExt {
				nameStr = "📄 " + r.Name
			} else {
				nameStr = "💻 " + r.Name
			}
			
			latencyStr := "N/A"
			if r.Connected && r.LatencyMs != 999 {
				latencyStr = fmt.Sprintf("%d", r.LatencyMs)
			}
			printRow([]string{
				nameStr,
				r.Address,
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


