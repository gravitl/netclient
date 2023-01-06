// This file contains methods intended to be called in frontend
package gui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/viper"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.design/x/clipboard"
)

// App.GoJoinNetworkByToken joins a network with the given token
func (app *App) GoJoinNetworkByToken(token string) (any, error) {
	// setup flag
	flags := viper.New()
	flags.Set("token", token)
	flags.Set("server", "")

	config.InitConfig(flags)
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

	// read fresh config from disk
	config.InitConfig(viper.New())

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
	// read fresh config from disk
	config.InitConfig(viper.New())

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

// App.GoGetRecentServerNames returns names of all known (joined) servers
func (app *App) GoGetRecentServerNames() ([]string, error) {
	serverNames := []string{}
	for name := range config.Servers {
		name := name
		serverNames = append(serverNames, name)
	}
	return serverNames, nil
}

// App.GoJoinNetworkBySso joins a network by SSO
func (app *App) GoJoinNetworkBySso(serverName, networkName string) (any, error) {
	flags := viper.New()
	flags.Set("server", serverName)
	flags.Set("network", networkName)

	config.InitConfig(flags)
	err := functions.Join(flags)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return nil, nil
}

// App.GoJoinNetworkByBasicAuth joins a network by basic auth
func (app *App) GoJoinNetworkByBasicAuth(serverName, username, networkName, password string) (any, error) {
	flags := viper.New()
	flags.Set("server", serverName)
	flags.Set("user", username)
	flags.Set("network", networkName)
	flags.Set("readPassFromStdIn", false)
	flags.Set("pass", password)

	config.InitConfig(flags)
	err := functions.Join(flags)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return nil, nil
}

// App.GoUninstall uninstalls netclient form the machine
func (app *App) GoUninstall() (any, error) {
	errs, err := functions.Uninstall()
	if len(errs) == 0 && err == nil {
		return nil, nil
	}
	errMsgsBuilder := strings.Builder{}
	for _, errMsg := range errs {
		errMsgsBuilder.WriteString(errMsg.Error() + " ")
	}
	return nil, fmt.Errorf("%w: "+errMsgsBuilder.String(), err)
}

// App.GoOpenDialogue opens a dialogue box with title and message.
// Type of dialogue box is based on the type passed
func (app *App) GoOpenDialogue(dialogueType runtime.DialogType, msg, title string) (string, error) {
	res, err := runtime.MessageDialog(app.ctx, runtime.MessageDialogOptions{
		Type:    dialogueType,
		Title:   title,
		Message: msg,
	})

	if err != nil {
		return "", err
	}

	return res, nil
}

// App.GoWriteToClipboard writes given data to clipboard
func (app *App) GoWriteToClipboard(data string) (any, error) {
	err := clipboard.Init()
	if err != nil {
		return nil, err
	}

	clipboard.Write(clipboard.FmtText, []byte(data))
	return nil, nil
}

// App.GoPullLatestNodeConfig pulls the latest node config from the server and returns the network config
func (app *App) GoPullLatestNodeConfig(network string) (Network, error) {
	node, err := functions.Pull(network, true)
	if err != nil {
		return Network{}, err
	}

	server := config.GetServer(node.Server)

	return Network{ Node: node, Server: server, }, nil
}
