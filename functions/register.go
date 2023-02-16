package functions

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/viper"
)

// Register - should be simple to register with a token
func Register(flags *viper.Viper) error {
	token := flags.GetString("token")
	data, err := b64.StdEncoding.DecodeString(token)
	if err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	var serverData models.EnrollmentToken
	if err = json.Unmarshal(data, &serverData); err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	host := config.Netclient()
	shouldUpdateHost, err := doubleCheck(host)
	if err != nil {
		logger.FatalLog(fmt.Sprintf("error when checking host values - %v", err.Error()))
	}
	if shouldUpdateHost { // get most up to date values before submitting to server
		host = config.Netclient()
	}
	api := httpclient.JSONEndpoint[models.ServerConfig, models.ErrorResponse]{
		URL:           "https://" + serverData.Server,
		Route:         "/api/v1/host/register" + token,
		Method:        http.MethodPost,
		Data:          host,
		Response:      models.ServerConfig{},
		ErrorResponse: models.ErrorResponse{},
	}
	joinResponse, errData, err := api.GetJSON(models.ServerConfig{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.FatalLog("error registering to server", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	config.UpdateServerConfig(&joinResponse)
	server := config.GetServer(joinResponse.Server)
	if err := config.SaveServer(serverData.Server, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saving netclient config", err.Error())
	}
	if err := daemon.Restart(); err != nil {
		logger.Log(3, "daemon restart failed:", err.Error())
	}
	fmt.Printf("Completed registration to server %s \n", serverData.Server)
	return nil
}