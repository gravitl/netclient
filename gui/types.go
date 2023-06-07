// this file contains types to serve as wrappers since wails supports only
// up to two function return values: (data, error) or (data)
// https://wails.io/docs/howdoesitwork#method-binding:~:text=The%20generated%20methods,passed%20to%20it.
package main

import "github.com/gravitl/netclient/config"

// Network describes a server netclient is connected to
// as well as nc itself's representation on a network
type Network struct {
	Node   *config.Node   `json:"node"`
	Server *config.Server `json:"server"`
}

// NcConfig is a wrapper of the host/netclient config for GUI
type NcConfig struct {
	config.Config
	MacAddressStr string `json:"macaddressstr"`
}

// SsoJoinResDto DTO for SSO join response
type SsoJoinResDto struct {
	Authendpoint string `json:"authendpoint"`
}
