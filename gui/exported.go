// This file contains methods intended to be called in frontend
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.design/x/clipboard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var headers []httpclient.Header

// App.GoGetStatus returns the status of the netclient http server
func (app *App) GoGetStatus() (any, error) {
	// set timeout to low value
	httpclient.Client.Timeout = 5 * time.Second
	defer func() {
		httpclient.Client.Timeout = 30 * time.Second
	}()

	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(nil, http.MethodGet, url+"/status", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, errors.New("netclient http server is not running or unreachable")
	}
	return nil, nil
}

// App.GoGetKnownNetworks returns all known network configs (node, server)
func (app *App) GoGetKnownNetworks() ([]Network, error) {
	networks := []Network{}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(nil, http.MethodGet, url+"/allnetworks", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return networks, err
	}
	if response.StatusCode != http.StatusOK {
		return networks, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&networks); err != nil {
		return networks, err
	}
	return networks, nil
}

// App.GoGetNetwork returns node, server configs for the given network
func (app *App) GoGetNetwork(networkName string) (Network, error) {
	network := Network{}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(nil, http.MethodGet, url+"/networks/"+networkName, "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return network, err
	}
	if response.StatusCode != http.StatusOK {
		return network, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&network); err != nil {
		return network, err
	}
	return network, nil
}

// App.GoGetNetclientConfig retrieves the netclient config
// (params the remain constant regardless the networks nc is connected to)
func (app *App) GoGetNetclientConfig() (NcConfig, error) {
	config := NcConfig{}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(nil, http.MethodGet, url+"/netclient", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return config, err
	}
	if response.StatusCode != http.StatusOK {
		return config, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&config); err != nil {
		return config, err
	}
	return config, nil
}

// App.goConnectToNetwork connects to the given network
func (app *App) GoConnectToNetwork(networkName string) (any, error) {
	connect := struct {
		Connect bool
	}{
		Connect: true,
	}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(connect, http.MethodPost, url+"/connect/"+networkName, "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
}

// App.goDisconnectFromNetwork disconnects from the given network
func (app *App) GoDisconnectFromNetwork(networkName string) (any, error) {
	connect := struct {
		Connect bool
	}{
		Connect: false,
	}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(connect, http.MethodPost, url+"/connect/"+networkName, "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
}

// App.GoLeaveNetwork leaves a known network
func (app *App) GoLeaveNetwork(networkName string) (any, error) {
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse("", http.MethodPost, url+"/leave/"+networkName, "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
}

// App.GoGetRecentServerNames returns names of all known (joined) servers
func (app *App) GoGetRecentServerNames() ([]string, error) {
	var servers struct {
		Name []string
	}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(nil, http.MethodGet, url+"/servers", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return []string{}, err
	}
	if response.StatusCode != http.StatusOK {
		return []string{}, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&servers); err != nil {
		return []string{}, err
	}
	return servers.Name, nil
}

// App.GoJoinNetworkBySso joins a network by SSO
func (app *App) GoJoinNetworkBySso(serverName, networkName string) (SsoJoinResDto, error) {
	payload := &functions.RegisterSSO{
		API:         serverName,
		Network:     networkName,
		UsingSSO:    true,
		AllNetworks: false,
	}
	res := SsoJoinResDto{}

	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(payload, http.MethodPost, url+"/sso/", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return res, err
	}
	if response.StatusCode != http.StatusOK {
		return res, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}

	if err := json.NewDecoder(response.Body).Decode(&res); err != nil {
		return res, err
	}
	return res, nil
}

// App.GoJoinNetworkByBasicAuth joins a network by username/password
func (app *App) GoJoinNetworkByBasicAuth(serverName, username, networkName, password string) (any, error) {
	payload := &functions.RegisterSSO{
		API:         serverName,
		Network:     networkName,
		UsingSSO:    false,
		User:        username,
		Pass:        password,
		AllNetworks: false,
	}

	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(payload, http.MethodPost, url+"/join/", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
}

// App.GoUninstall uninstalls netclient form the machine
func (app *App) GoUninstall() (any, error) {
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse("", http.MethodPost, url+"/uninstall/", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
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
	err := functions.Pull(true)
	if err != nil {
		return Network{}, err
	}

	return Network{}, nil
}

// App.GoGetNodePeers returns the peers for the given node
func (app *App) GoGetNodePeers(node config.Node) ([]wgtypes.PeerConfig, error) {
	var peers []wgtypes.PeerConfig
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(node, http.MethodPost, url+"/nodepeers", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return peers, err
	}
	if response.StatusCode != http.StatusOK {
		return peers, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&peers); err != nil {
		return peers, err
	}
	return peers, nil
}

// App.GoUpdateNetclientConfig updates netclient/host configs
func (app *App) GoUpdateNetclientConfig(updatedConfig config.Config) (any, error) {
	// should update in-memory config
	// should update on-disk config
	// should send MQ updates to all registered servers
	panic("unimplemented function")
}

func (app *App) GoRegisterWithEnrollmentKey(key string) (any, error) {
	token := struct {
		Token string
	}{
		Token: key,
	}
	var response *http.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = httpclient.GetResponse(token, http.MethodPost, url+"/register/", "", headers)
		if err == nil && response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status err %d %s", response.StatusCode, response.Status)
	}
	return nil, nil
}
