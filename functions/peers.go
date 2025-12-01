package functions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/wireguard"
)

type peerInfo struct {
	PublicKey           string    `json:"public_key"`
	HostName            string    `json:"host_name,omitempty"`
	Network             string    `json:"network,omitempty"`
	Endpoint            string    `json:"endpoint,omitempty"`
	LastHandshake       string    `json:"last_handshake,omitempty"`
	LastHandshakeTime   time.Time `json:"last_handshake_time,omitempty"`
	ReceiveBytes        int64     `json:"receive_bytes"`
	TransmitBytes       int64     `json:"transmit_bytes"`
	AllowedIPs          []string  `json:"allowed_ips,omitempty"`
	PersistentKeepalive string    `json:"persistent_keepalive,omitempty"`
}

// ShowPeers displays peer information from the WireGuard interface,
// grouped per network. If networkFilter is non-empty, only that
// network's peers are displayed.
func ShowPeers(jsonOutput bool, networkFilter string) error {
	ifaceName := ncutils.GetInterfaceName()
	devicePeers, err := wireguard.GetPeersFromDevice(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get peers from device %s: %w", ifaceName, err)
	}

	if len(devicePeers) == 0 {
		if jsonOutput {
			fmt.Println("[]")
		} else {
			fmt.Println("\nNo peers found on interface", ifaceName)
		}
		return nil
	}

	// Get additional metadata (including host names and network mapping) from server
	hostPeerInfo, err := networking.GetPeerInfo()
	if err != nil {
		return fmt.Errorf("failed to fetch peer metadata from server: %w", err)
	}

	// Build network -> []peerInfo map
	networkPeers := make(map[string][]peerInfo)

	for networkID, peerMap := range hostPeerInfo.NetworkPeerIDs {
		netName := string(networkID)
		if networkFilter != "" && netName != networkFilter {
			continue
		}
		for pubKey, idAndAddr := range peerMap {
			devicePeer, ok := devicePeers[pubKey]
			if !ok {
				// No live WireGuard peer for this pubkey on the device; skip
				continue
			}

			info := peerInfo{
				PublicKey:     devicePeer.PublicKey.String(),
				HostName:      idAndAddr.Name,
				Network:       idAndAddr.Network,
				ReceiveBytes:  devicePeer.ReceiveBytes,
				TransmitBytes: devicePeer.TransmitBytes,
			}

			if devicePeer.Endpoint != nil {
				info.Endpoint = devicePeer.Endpoint.String()
			}

			if !devicePeer.LastHandshakeTime.IsZero() {
				info.LastHandshakeTime = devicePeer.LastHandshakeTime
				timeSince := time.Since(devicePeer.LastHandshakeTime)
				if timeSince < time.Minute {
					info.LastHandshake = fmt.Sprintf("%.0f seconds ago", timeSince.Seconds())
				} else if timeSince < time.Hour {
					info.LastHandshake = fmt.Sprintf("%.0f minutes ago", timeSince.Minutes())
				} else if timeSince < 24*time.Hour {
					info.LastHandshake = fmt.Sprintf("%.1f hours ago", timeSince.Hours())
				} else {
					info.LastHandshake = fmt.Sprintf("%.1f days ago", timeSince.Hours()/24)
				}
			} else {
				info.LastHandshake = "never"
			}

			if len(devicePeer.AllowedIPs) > 0 {
				info.AllowedIPs = make([]string, 0, len(devicePeer.AllowedIPs))
				for _, ip := range devicePeer.AllowedIPs {
					info.AllowedIPs = append(info.AllowedIPs, ip.String())
				}
			}

			if devicePeer.PersistentKeepaliveInterval > 0 {
				info.PersistentKeepalive = devicePeer.PersistentKeepaliveInterval.String()
			}

			networkPeers[netName] = append(networkPeers[netName], info)
		}
	}

	if len(networkPeers) == 0 {
		if networkFilter != "" {
			fmt.Println("\nNo peers found for network", networkFilter)
		} else {
			fmt.Println("\nNo peers found across any networks")
		}
		return nil
	}

	if jsonOutput {
		out, err := json.MarshalIndent(networkPeers, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal peer info: %w", err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("\nPeer information for interface: %s\n\n", ifaceName)

		// Sort networks for stable output
		networks := make([]string, 0, len(networkPeers))
		for n := range networkPeers {
			networks = append(networks, n)
		}
		sort.Strings(networks)

		headers := []string{
			"INDEX",
			"NETWORK",
			"HOSTNAME",
			"PUBLIC KEY",
			"ENDPOINT",
			"LAST HANDSHAKE",
			"RECEIVED",
			"SENT",
			"KEEPALIVE",
			"ALLOWED IPS",
		}

		for _, netName := range networks {
			peers := networkPeers[netName]
			fmt.Printf("Network: %s\n", netName)

			rows := make([][]string, 0, len(peers))
			for i, info := range peers {
				allowed := ""
				if len(info.AllowedIPs) > 0 {
					allowed = strings.Join(info.AllowedIPs, ",")
				}
				rows = append(rows, []string{
					fmt.Sprintf("%d", i+1),
					info.Network,
					info.HostName,
					info.PublicKey,
					info.Endpoint,
					info.LastHandshake,
					formatBytes(info.ReceiveBytes),
					formatBytes(info.TransmitBytes),
					info.PersistentKeepalive,
					allowed,
				})
			}

			printBorderedTable(headers, rows)
			fmt.Println()
		}
	}

	return nil
}

// printBorderedTable prints a simple ASCII table with borders around headers, rows, and columns.
// Long text in HOSTNAME and ALLOWED IPS columns will wrap to multiple lines within the same cell.
func printBorderedTable(headers []string, rows [][]string) {
	colCount := len(headers)
	widths := make([]int, colCount)

	// Find indices of columns that should wrap (HOSTNAME and ALLOWED IPS)
	hostnameIdx := -1
	allowedIPsIdx := -1
	for i, h := range headers {
		if h == "HOSTNAME" {
			hostnameIdx = i
		} else if h == "ALLOWED IPS" {
			allowedIPsIdx = i
		}
	}

	// Set max widths for wrapable columns
	const maxHostnameWidth = 25
	const maxAllowedIPsWidth = 30

	// Initialize widths with header lengths
	for i, h := range headers {
		widths[i] = len(h)
	}

	// Adjust widths based on row contents, but cap wrapable columns
	for _, row := range rows {
		for i := 0; i < colCount && i < len(row); i++ {
			cellLen := len(row[i])
			if i == hostnameIdx && cellLen > maxHostnameWidth {
				// For hostname, use max width
				if maxHostnameWidth > widths[i] {
					widths[i] = maxHostnameWidth
				}
			} else if i == allowedIPsIdx && cellLen > maxAllowedIPsWidth {
				// For allowed IPs, use max width
				if maxAllowedIPsWidth > widths[i] {
					widths[i] = maxAllowedIPsWidth
				}
			} else {
				// For other columns, use actual content length
				if cellLen > widths[i] {
					widths[i] = cellLen
				}
			}
		}
	}

	// Wrap cells that need wrapping and prepare multi-line rows
	type cellLines struct {
		lines []string
	}
	multiLineRows := make([][]cellLines, len(rows))

	for rIdx, row := range rows {
		multiLineRows[rIdx] = make([]cellLines, colCount)
		maxLines := 1

		// Process each cell and wrap if needed
		for i := 0; i < colCount; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}

			if i == hostnameIdx && len(cell) > maxHostnameWidth {
				// Wrap hostname
				lines := wrapText(cell, maxHostnameWidth)
				multiLineRows[rIdx][i].lines = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			} else if i == allowedIPsIdx && len(cell) > maxAllowedIPsWidth {
				// Wrap allowed IPs (split by comma first, then wrap)
				lines := wrapAllowedIPs(cell, maxAllowedIPsWidth)
				multiLineRows[rIdx][i].lines = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			} else {
				// Single line cell
				multiLineRows[rIdx][i].lines = []string{cell}
			}
		}

		// Pad all cells in this row to have the same number of lines
		for i := 0; i < colCount; i++ {
			for len(multiLineRows[rIdx][i].lines) < maxLines {
				multiLineRows[rIdx][i].lines = append(multiLineRows[rIdx][i].lines, "")
			}
		}
	}

	printSeparator := func() {
		fmt.Print("+")
		for i := 0; i < colCount; i++ {
			fmt.Print(strings.Repeat("-", widths[i]+2))
			fmt.Print("+")
		}
		fmt.Println()
	}

	printRowLine := func(lineCells []string) {
		fmt.Print("|")
		for i := 0; i < colCount; i++ {
			cell := ""
			if i < len(lineCells) {
				cell = lineCells[i]
			}
			// left pad with a space, right pad to width, then trailing space
			fmt.Printf(" %-*s |", widths[i], cell)
		}
		fmt.Println()
	}

	// Header
	printSeparator()
	printRowLine(headers)
	printSeparator()

	// Rows - print each line of multi-line cells with row borders
	for rowIdx, multiRow := range multiLineRows {
		lineCount := len(multiRow[0].lines)
		for lineIdx := 0; lineIdx < lineCount; lineIdx++ {
			lineCells := make([]string, colCount)
			for i := 0; i < colCount; i++ {
				if lineIdx < len(multiRow[i].lines) {
					lineCells[i] = multiRow[i].lines[lineIdx]
				}
			}
			printRowLine(lineCells)
		}
		// Add row border after each complete row (except after the last row)
		if rowIdx < len(multiLineRows)-1 {
			printSeparator()
		}
	}
	printSeparator()
}

// wrapText wraps a string to fit within maxWidth, breaking at word boundaries when possible
func wrapText(text string, maxWidth int) []string {
	if len(text) <= maxWidth {
		return []string{text}
	}

	var lines []string
	remaining := text

	for len(remaining) > maxWidth {
		// Try to break at a space or comma
		breakIdx := maxWidth
		for i := maxWidth; i > 0; i-- {
			if i < len(remaining) && (remaining[i] == ' ' || remaining[i] == ',' || remaining[i] == '-') {
				breakIdx = i + 1
				break
			}
		}
		lines = append(lines, remaining[:breakIdx])
		remaining = strings.TrimLeft(remaining[breakIdx:], " ,-")
	}

	if len(remaining) > 0 {
		lines = append(lines, remaining)
	}

	return lines
}

// wrapAllowedIPs wraps allowed IPs, trying to keep IPs together and breaking at commas
func wrapAllowedIPs(text string, maxWidth int) []string {
	if len(text) <= maxWidth {
		return []string{text}
	}

	// Split by comma first
	parts := strings.Split(text, ",")
	var lines []string
	currentLine := ""

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// If adding this part would exceed maxWidth, start a new line
		candidate := currentLine
		if candidate != "" {
			candidate += "," + part
		} else {
			candidate = part
		}

		if len(candidate) <= maxWidth {
			currentLine = candidate
		} else {
			// Current line is full, save it and start new
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			// If the part itself is too long, wrap it
			if len(part) > maxWidth {
				wrapped := wrapText(part, maxWidth)
				lines = append(lines, wrapped[0])
				if len(wrapped) > 1 {
					currentLine = strings.Join(wrapped[1:], "")
				} else {
					currentLine = ""
				}
			} else {
				currentLine = part
			}
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
