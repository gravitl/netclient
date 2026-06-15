package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
)

// IsRegisteredToServer reports whether netclient is registered to the given server.
func IsRegisteredToServer(server string) bool {
	if server == "" {
		return false
	}
	return config.GetServer(server) != nil
}

// RegisterSession registers or refreshes a desktop UI session against a server.
func RegisterSession(server, username, authToken, password string) error {
	if server == "" {
		return fmt.Errorf("server not configured")
	}
	if username == "" || authToken == "" {
		return fmt.Errorf("username and auth token are required")
	}

	if IsRegisteredToServer(server) {
		if config.CurrServer != server {
			if err := config.SetCurrServerCtxInFile(server); err != nil {
				return err
			}
			config.CurrServer = server
		}
		if _, _, _, err := Pull(false, true); err != nil {
			return fmt.Errorf("failed to sync with server: %w", err)
		}
		return nil
	}

	if password != "" {
		return RegisterWithSSO(&RegisterSSO{
			API:         server,
			User:        username,
			Pass:        password,
			AllNetworks: true,
		})
	}

	return RegisterWithSSO(&RegisterSSO{
		API:         server,
		User:        username,
		Pass:        authToken,
		AllNetworks: true,
	})
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
	return nil
}
