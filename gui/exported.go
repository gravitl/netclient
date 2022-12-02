// This file contains methods intended to be called in frontend
package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/viper"
)

// App.GoJoinNetworkByToken joins a network with the given token
func (app *App) GoJoinNetworkByToken(token string) (any, error) {
	// setup flag
	flags := viper.New()
	flags.Set("token", token)
	flags.Set("server", "")

	err := functions.Join(flags)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return nil, nil
}

// App.GoGetKnownNetworks returns all known network configs (node, server)
func (app *App) GoGetKnownNetworks() ([]Network, error) {
	configs := make([]Network, 0, 5)

	nodesMap := config.GetNodes()
	for _, node := range nodesMap {
		node := node
		server := config.GetServer(node.Server)
		configs = append(configs, Network{&node, server})
	}

	return configs, nil
}

// App.GoGetNetwork returns node, server configs for the given network
func (app *App) GoGetNetwork(networkName string) (Network, error) {
	nodesMap := config.GetNodes()
	for _, node := range nodesMap {
		if node.Network == networkName {
			server := config.GetServer(node.Server)
			return Network{&node, server}, nil
		}
	}

	return Network{}, errors.New("unknown network")
}

// App.GoGetNetclientConfig retrieves the netclient config
// (params the remain constant regardless the networks nc is connected to)
func (app *App) GoGetNetclientConfig() (config.Config, error) {
	return *config.Netclient(), nil
}

// App.GoParseAccessToken parses a valid access token and returns the deconstructed parts
func (app *App) GoParseAccessToken(token string) (*models.AccessToken, error) {
	return config.ParseAccessToken(token)
}

// App.goConnectToNetwork connects to the given network
func (app *App) GoConnectToNetwork(networkName string) (any, error) {
	return nil, functions.Connect(networkName)
}

// App.goDisconnectFromNetwork disconnects from the given network
func (app *App) GoDisconnectFromNetwork(networkName string) (any, error) {
	return nil, functions.Disconnect(networkName)
}

// App.GoLeaveNetwork leaves a known network
func (app *App) GoLeaveNetwork(networkName string) (any, error) {
	errs, err := functions.LeaveNetwork(networkName)
	if len(errs) == 0 && err == nil {
		return nil, nil
	}
	errMsgsBuilder := strings.Builder{}
	for _, errMsg := range errs {
		errMsgsBuilder.WriteString(errMsg.Error() + " ")
	}
	return nil, fmt.Errorf("%w: "+errMsgsBuilder.String(), err)
}
