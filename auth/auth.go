// Package auth provides netclient auth logic with server
package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/routes"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Authenticate authenticates with netmaker api to permit subsequent interactions with the api
func Authenticate(server *config.Server, host *config.Config) (string, error) {
	data := models.AuthParams{
		MacAddress: host.MacAddress.String(),
		ID:         host.ID.String(),
		Password:   host.HostPass,
	}
	endpoint := httpclient.Endpoint{
		URL:    "https://" + server.API,
		Route:  "/api/hosts/adm/authenticate",
		Method: http.MethodPost,
		Data:   data,
	}
	response, err := endpoint.GetResponse()
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		bodybytes, _ := io.ReadAll(response.Body)
		if response.StatusCode == http.StatusUnauthorized { // if host is unauthorized, clean-up locally
			if err := cleanUpByServer(server); err != nil {
				return "", err
			} else {
				return "", fmt.Errorf("unauthorized request - removed instances for %s", server.Name)
			}
		}
		return "", fmt.Errorf("failed to authenticate %s %s", response.Status, string(bodybytes))
	}
	resp := models.SuccessResponse{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("error decoding respone %w", err)
	}
	tokenData := resp.Response.(map[string]interface{})
	token := tokenData["AuthToken"]
	return token.(string), nil
}

func cleanUpByServer(server *config.Server) error {
	if err := config.ReadNodeConfig(); err != nil {
		return err
	}
	if err := config.ReadServerConf(); err != nil {
		return err
	}
	if _, err := config.ReadNetclientConfig(); err != nil {
		return err
	}
	serverNodes := config.GetNodes()
	for i := range serverNodes {
		node := serverNodes[i]
		config.DeleteNode(node.Network)
	}
	if err := config.WriteNodeConfig(); err != nil {
		return err
	}
	config.RemoveServerHostPeerCfg()
	if err := wireguard.SetPeers(true); err != nil {
		logger.Log(0, "interface not up, failed to remove peers for %s \n", server.Name)
	}
	if err := routes.CleanUp(config.Netclient().DefaultInterface, nil); err != nil {
		return err
	}
	config.DeleteServerHostPeerCfg()
	if err := config.WriteNetclientConfig(); err != nil {
		return err
	}
	config.DeleteServer(server.Name)
	if err := config.WriteServerConfig(); err != nil {
		return err
	}
	_ = daemon.Restart()
	return nil
}
