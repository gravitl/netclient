package wireguard

import (
	"encoding/json"
	"fmt"
	"strings"
)

// dnsClientServerEntry is one row from Get-DnsClientServerAddress | ConvertTo-Json.
type dnsClientServerEntry struct {
	InterfaceIndex  int      `json:"InterfaceIndex"`
	ServerAddresses []string `json:"ServerAddresses"`
}

// parseDnsClientServerAddressJSON accepts either a JSON array or a single object.
// PowerShell's ConvertTo-Json emits an object (not an array) when only one row
// is returned; treating that as a hard failure left the netmaker iface metric
// unset and made Windows prefer Netclient for general DNS.
func parseDnsClientServerAddressJSON(output string) ([]dnsClientServerEntry, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, fmt.Errorf("empty dns client server address output")
	}

	var entries []dnsClientServerEntry
	if err := json.Unmarshal([]byte(output), &entries); err == nil {
		return entries, nil
	}

	var single dnsClientServerEntry
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, fmt.Errorf("parse dns client server addresses: %w", err)
	}
	return []dnsClientServerEntry{single}, nil
}
