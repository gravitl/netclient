// Package auth provides netclient auth logic with server
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	jwtToken     string
	jwtSecretKey []byte
)

func isTokenExpired(tokenString string) bool {
	claims := &models.Claims{}
	token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if token != nil {
		if claims.ExpiresAt.Unix() != 0 && claims.ExpiresAt.Unix() > time.Now().Unix() {
			return false
		}
	}

	return true
}

func CleanJwtToken() {
	jwtToken = ""
}

// Authenticate authenticates with netmaker api to permit subsequent interactions with the api
func Authenticate(server *config.Server, host *config.Config) (string, error) {
	if jwtToken != "" && !isTokenExpired(jwtToken) {
		return jwtToken, nil
	}
	data := models.AuthParams{
		MacAddress: host.MacAddress.String(),
		ID:         host.ID.String(),
		Password:   host.HostPass,
	}

	url := fmt.Sprintf("https://%s/api/hosts/adm/authenticate", server.API)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	respBytes, err := ncutils.SendRequest(http.MethodPost, url, headers, data)
	if err != nil {
		var notOkErr ncutils.ErrStatusNotOk
		if errors.As(err, &notOkErr) {
			if notOkErr.Status == http.StatusUnauthorized {
				if err := cleanUpByServer(server); err != nil {
					return "", err
				}

				return "", fmt.Errorf("unauthorized request - removed instances for %s", server.Name)
			}

			return "", fmt.Errorf("failed to authenticate %d %s", notOkErr.Status, notOkErr.Message)
		}

		return "", err
	}

	var resp models.SuccessResponse
	err = json.Unmarshal(respBytes.Bytes(), &resp)
	if err != nil {
		return "", fmt.Errorf("error decoding response %w", err)
	}

	tokenData := resp.Response.(map[string]interface{})
	token := tokenData["AuthToken"]
	jwtToken = token.(string)
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
