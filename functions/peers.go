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
	"golang.zx2c4.com/wireguard/wgctrl"
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
	IsExt               bool      `json:"is_extclient,omitempty"`
	UserName            string    `json:"username,omitempty"`
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

	// Get device information (port and public key)
	var interfacePort int
	var interfacePublicKey string
	wg, err := wgctrl.New()
	if err == nil {
		defer wg.Close()
		device, err := wg.Device(ifaceName)
		if err == nil {
			interfacePort = device.ListenPort
			interfacePublicKey = device.PublicKey.String()
		}
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
				IsExt:         idAndAddr.IsExtClient,
				UserName:      idAndAddr.UserName,
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
		// Include interface info in JSON output
		output := map[string]interface{}{
			"interface": map[string]interface{}{
				"name":       ifaceName,
				"port":       interfacePort,
				"public_key": interfacePublicKey,
			},
			"peers": networkPeers,
		}
		out, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal peer info: %w", err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("\nInterface: %s\n", ifaceName)
		if interfacePort > 0 {
			fmt.Printf("Interface Port: %d\n", interfacePort)
		}
		if interfacePublicKey != "" {
			fmt.Printf("Interface Public Key: %s\n", interfacePublicKey)
		}
		fmt.Println()

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
				// Format hostname with emoji prefix: 👤 for users with username, 📄 for external clients, 💻 for regular devices
				// When username is set, display username instead of hostname
				var hostnameStr string
				if info.UserName != "" {
					hostnameStr = "👤 " + info.UserName
				} else if info.IsExt {
					hostnameStr = "📄 " + info.HostName
				} else {
					hostnameStr = "💻 " + info.HostName
				}
				rows = append(rows, []string{
					fmt.Sprintf("%d", i+1),
					info.Network,
					hostnameStr,
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

	// Initialize widths with header display widths
	for i, h := range headers {
		widths[i] = displayWidth(h)
	}

	// Adjust widths based on row contents, but cap wrapable columns
	for _, row := range rows {
		for i := 0; i < colCount && i < len(row); i++ {
			cellWidth := displayWidth(row[i])
			if i == hostnameIdx && cellWidth > maxHostnameWidth {
				// For hostname, use max width
				if maxHostnameWidth > widths[i] {
					widths[i] = maxHostnameWidth
				}
			} else if i == allowedIPsIdx && cellWidth > maxAllowedIPsWidth {
				// For allowed IPs, use max width
				if maxAllowedIPsWidth > widths[i] {
					widths[i] = maxAllowedIPsWidth
				}
			} else {
				// For other columns, use actual content display width
				if cellWidth > widths[i] {
					widths[i] = cellWidth
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

			if i == hostnameIdx && displayWidth(cell) > maxHostnameWidth {
				// Wrap hostname
				lines := wrapText(cell, maxHostnameWidth)
				multiLineRows[rIdx][i].lines = lines
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			} else if i == allowedIPsIdx && displayWidth(cell) > maxAllowedIPsWidth {
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
			fmt.Print(" ")
			fmt.Print(padRight(cell, widths[i]))
			fmt.Print(" |")
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
// If a word is too long, it will be broken at character boundaries
func wrapText(text string, maxWidth int) []string {
	if displayWidth(text) <= maxWidth {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	currentLine := ""

	for _, word := range words {
		wordWidth := displayWidth(word)

		// If a single word exceeds maxWidth, break it at character boundaries
		if wordWidth > maxWidth {
			// First, save current line if it has content
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = ""
			}

			// Break the long word into chunks
			var wordChars []rune
			for _, r := range word {
				wordChars = append(wordChars, r)
			}

			currentChunk := ""
			for _, char := range wordChars {
				testChunk := currentChunk + string(char)
				if displayWidth(testChunk) <= maxWidth {
					currentChunk = testChunk
				} else {
					if currentChunk != "" {
						lines = append(lines, currentChunk)
					}
					currentChunk = string(char)
				}
			}
			if currentChunk != "" {
				currentLine = currentChunk
			}
		} else {
			// Normal word that fits - try to add it to current line
			testLine := currentLine
			if testLine != "" {
				testLine += " " + word
			} else {
				testLine = word
			}

			if displayWidth(testLine) <= maxWidth {
				currentLine = testLine
			} else {
				// Word doesn't fit on current line
				if currentLine != "" {
					lines = append(lines, currentLine)
				}
				currentLine = word
			}
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	return lines
}

// wrapAllowedIPs wraps a comma-separated list of IPs to fit within maxWidth
func wrapAllowedIPs(ips string, maxWidth int) []string {
	if displayWidth(ips) <= maxWidth {
		return []string{ips}
	}

	var lines []string
	parts := strings.Split(ips, ",")
	currentLine := ""

	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if currentLine == "" {
			currentLine = trimmedPart
		} else if displayWidth(currentLine+","+trimmedPart) <= maxWidth {
			currentLine += "," + trimmedPart
		} else {
			lines = append(lines, currentLine)
			currentLine = trimmedPart
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
