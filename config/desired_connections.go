package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	desiredConnectionsFile     = "desired_connections.json"
	desiredConnectionsLockfile = "netclient-desired-connections.lck"
)

// DesiredState is the reconnect record for one user+tenant on this host.
type DesiredState struct {
	Networks []string `json:"networks"`
	WantIGW  bool     `json:"want_igw"`
}

// desiredConnectionsStore is username → tenant ID → network state.
type desiredConnectionsStore map[string]map[string]DesiredState

var (
	desiredConnectionsMu  sync.Mutex
	desiredConnectionsDir string // tests may override
)

func desiredConnectionsPath() string {
	dir := desiredConnectionsDir
	if dir == "" {
		dir = GetNetclientPath()
	}
	return filepath.Join(dir, desiredConnectionsFile)
}

func desiredConnectionsLockPath() string {
	return filepath.Join(os.TempDir(), desiredConnectionsLockfile)
}

func sessionUserTenant(username, tenantID string) (string, string, bool) {
	username = strings.TrimSpace(username)
	tenantID = strings.TrimSpace(tenantID)
	if username == "" || tenantID == "" {
		return "", "", false
	}
	return username, tenantID, true
}

func userState(store desiredConnectionsStore, username, tenantID string) DesiredState {
	username, tenantID, ok := sessionUserTenant(username, tenantID)
	if !ok {
		return DesiredState{}
	}
	if tenants, ok := store[username]; ok {
		return tenants[tenantID]
	}
	return DesiredState{}
}

func putUserState(store desiredConnectionsStore, username, tenantID string, state DesiredState) bool {
	username, tenantID, ok := sessionUserTenant(username, tenantID)
	if !ok {
		return false
	}
	state.Networks = uniqueNetworks(state.Networks)
	tenants := store[username]
	if tenants == nil {
		tenants = make(map[string]DesiredState)
		store[username] = tenants
	}
	tenants[tenantID] = state
	return true
}

// GetDesiredNetworks returns networks this user should auto-connect on login/reboot.
func GetDesiredNetworks(username, tenantID string) []string {
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	nets := userState(store, username, tenantID).Networks
	out := make([]string, len(nets))
	copy(out, nets)
	return out
}

// SetDesiredNetworks replaces the auto-connect list for a user+tenant.
func SetDesiredNetworks(username, tenantID string, networks []string) error {
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	state := userState(store, username, tenantID)
	state.Networks = uniqueNetworks(networks)
	if !putUserState(store, username, tenantID, state) {
		return nil
	}
	return writeDesiredConnectionsLocked(store)
}

// SnapshotDesiredState records networks to restore and whether an exit node
// was active, so login/reboot can wait for ChangeDefaultGw before applying routes.
func SnapshotDesiredState(username, tenantID string, networks []string, wantIGW bool) error {
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	if !putUserState(store, username, tenantID, DesiredState{
		Networks: uniqueNetworks(networks),
		WantIGW:  wantIGW,
	}) {
		return nil
	}
	return writeDesiredConnectionsLocked(store)
}

// GetDesiredWantIGW reports whether this user should restore internet-exit routing.
func GetDesiredWantIGW(username, tenantID string) bool {
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	return userState(store, username, tenantID).WantIGW
}

// SetDesiredWantIGW updates only the exit-restore flag for a user+tenant.
func SetDesiredWantIGW(username, tenantID string, wantIGW bool) error {
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	state := userState(store, username, tenantID)
	state.WantIGW = wantIGW
	if !putUserState(store, username, tenantID, state) {
		return nil
	}
	return writeDesiredConnectionsLocked(store)
}

// RememberDesiredNetwork records that the user connected this network.
func RememberDesiredNetwork(username, tenantID, network string) error {
	network = strings.TrimSpace(network)
	if network == "" {
		return nil
	}
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	state := userState(store, username, tenantID)
	state.Networks = appendUniqueNetwork(state.Networks, network)
	if !putUserState(store, username, tenantID, state) {
		return nil
	}
	return writeDesiredConnectionsLocked(store)
}

// ForgetDesiredNetwork records that the user disconnected or left this network.
func ForgetDesiredNetwork(username, tenantID, network string) error {
	network = strings.TrimSpace(network)
	if network == "" {
		return nil
	}
	desiredConnectionsMu.Lock()
	defer desiredConnectionsMu.Unlock()
	store := readDesiredConnectionsLocked()
	state := userState(store, username, tenantID)
	state.Networks = removeNetwork(state.Networks, network)
	if !putUserState(store, username, tenantID, state) {
		return nil
	}
	return writeDesiredConnectionsLocked(store)
}

func readDesiredConnectionsLocked() desiredConnectionsStore {
	data, err := os.ReadFile(desiredConnectionsPath())
	if err != nil {
		return desiredConnectionsStore{}
	}
	var store desiredConnectionsStore
	if err := json.Unmarshal(data, &store); err != nil || store == nil {
		return desiredConnectionsStore{}
	}
	return store
}

func writeDesiredConnectionsLocked(store desiredConnectionsStore) error {
	if store == nil {
		store = desiredConnectionsStore{}
	}
	return WriteJSONAtomic(desiredConnectionsPath(), store, desiredConnectionsLockPath(), 0600)
}

func uniqueNetworks(networks []string) []string {
	seen := make(map[string]struct{}, len(networks))
	out := make([]string, 0, len(networks))
	for _, n := range networks {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func appendUniqueNetwork(list []string, network string) []string {
	out := removeNetwork(list, network)
	return append(out, network)
}

func removeNetwork(list []string, network string) []string {
	if len(list) == 0 {
		return list
	}
	out := make([]string, 0, len(list))
	for _, n := range list {
		if n == network {
			continue
		}
		out = append(out, n)
	}
	return out
}
