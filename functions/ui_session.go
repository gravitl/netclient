package functions

import (
	"fmt"
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
)

var (
	registerDeviceOnServerForSession = RegisterDeviceOnServer
	pullForDesktopForSession         = PullForDesktop
)

// IsRegisteredToServer reports whether netclient is registered to the given server.
func IsRegisteredToServer(server string) bool {
	return config.ResolveServerKey(server) != ""
}

// RegisterSession registers or refreshes a desktop UI session against a server.
// password is ignored (legacy desktop clients may still send it); authToken must be the user JWT.
func RegisterSession(server, username, authToken, password string) error {
	_ = password
	server = strings.TrimPrefix(strings.TrimSpace(server), "https://")
	if server == "" {
		return fmt.Errorf("server not configured")
	}
	if username == "" || authToken == "" {
		return fmt.Errorf("username and auth token are required")
	}
	if key := config.ResolveServerKey(server); key != "" {
		server = key
	}

	if config.CurrServer != server {
		if err := config.SetCurrServerCtxInFile(server); err != nil {
			return err
		}
		config.CurrServer = server
	}

	if !IsRegisteredToServer(server) {
		if err := registerDeviceOnServerForSession(server, authToken); err != nil {
			return err
		}
	}

	if IsRegisteredToServer(server) {
		if _, _, _, err := pullForDesktopForSession(false, true); err != nil {
			return fmt.Errorf("failed to sync with server: %w", err)
		}
	}
	return nil
}

// ReleaseSession disconnects all networks and optionally clears server context.
func ReleaseSession(clearServer bool) error {
	networks := make([]string, 0, len(config.GetNodes()))
	for network, node := range config.GetNodes() {
		if node.Connected {
			networks = append(networks, network)
		}
	}
	for _, network := range networks {
		if err := Disconnect(network); err != nil {
			return err
		}
	}
	if clearServer {
		config.CurrServer = ""
		_ = config.SetCurrServerCtxInFile("")
	}
	auth.CleanJwtToken()
	return nil
}
