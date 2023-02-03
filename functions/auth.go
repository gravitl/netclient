// Package functions provides netclient logic
package functions

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
)

// Authenticate authenticates with netmaker api to permit subsequent interactions with the api
func Authenticate(url string, host *config.Config) (string, error) {
	data := models.AuthParams{
		MacAddress: host.MacAddress.String(),
		ID:         host.ID.String(),
		Password:   host.HostPass,
	}
	endpoint := httpclient.Endpoint{
		URL:    "https://" + url,
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
