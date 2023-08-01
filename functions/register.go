package functions

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Register - should be simple to register with a token
func Register(token string, isGui bool) error {
	data, err := b64.StdEncoding.DecodeString(token)
	if err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	var serverData models.EnrollmentToken
	if err = json.Unmarshal(data, &serverData); err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	host := config.Netclient()
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			host.Interfaces = *ip
		}
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else if defaultInterface != ncutils.GetInterfaceName() {
		host.DefaultInterface = defaultInterface
	}
	shouldUpdateHost, err := doubleCheck(host, serverData.Server)
	if err != nil {
		logger.FatalLog(fmt.Sprintf("error when checking host values - %v", err.Error()))
	}
	if shouldUpdateHost { // get most up to date values before submitting to server
		host = config.Netclient()
	}
	api := httpclient.JSONEndpoint[models.RegisterResponse, models.ErrorResponse]{
		URL:           "https://" + serverData.Server,
		Route:         "/api/v1/host/register/" + token,
		Method:        http.MethodPost,
		Data:          host,
		Response:      models.RegisterResponse{},
		ErrorResponse: models.ErrorResponse{},
	}
	registerResponse, errData, err := api.GetJSON(models.RegisterResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.FatalLog("error registering with server", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	if config.CurrServer != "" && config.CurrServer != registerResponse.ServerConf.Server {
		fmt.Println("WARNING: Joining any network on another server will disconnect netclient from the networks of the current server ->", config.CurrServer)
	}
	handleRegisterResponse(&registerResponse, isGui)
	return nil
}

func doubleCheck(host *config.Config, apiServer string) (shouldUpdate bool, err error) {
	var shouldUpdateHost bool

	if len(config.CurrServer) == 0 { // should indicate a first join
		// do a double check of name and uuid
		logger.Log(1, "performing first join")
		if len(host.Name) == 0 {
			if name, err := os.Hostname(); err == nil {
				host.Name = name
			} else {
				hostName := ncutils.RandomString(12)
				logger.Log(0, "host name not found, continuing with", hostName)
				host.Name = hostName
			}
			shouldUpdateHost = true
		}
		if host.ID == uuid.Nil {
			if host.ID, err = uuid.NewUUID(); err != nil {
				return false, err
			}
			shouldUpdateHost = true
		}
		if len(host.HostPass) == 0 {
			host.HostPass = ncutils.RandomString(32)
			shouldUpdateHost = true
		}
	}

	if host.EndpointIP == nil || host.WgPublicListenPort == 0 || host.NatType == "" {
		publicIp, publicPort, natType := holePunchWgPort()
		host.EndpointIP = publicIp
		host.WgPublicListenPort = publicPort
		host.NatType = natType
		shouldUpdateHost = true
	}

	if shouldUpdateHost {
		config.UpdateNetclient(*host)
		config.WriteNetclientConfig()
		return true, nil
	}
	return
}

func handleRegisterResponse(registerResponse *models.RegisterResponse, isGui bool) {
	config.UpdateServerConfig(&registerResponse.ServerConf)
	server := config.GetServer(registerResponse.ServerConf.Server)
	if err := config.SaveServer(registerResponse.ServerConf.Server, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	config.UpdateHost(&registerResponse.RequestedHost)
	config.SetCurrServerCtxInFile(server.Server)
	if !isGui {
		if err := daemon.Restart(); err != nil {
			logger.Log(3, "daemon restart failed:", err.Error())
		}
	}
	fmt.Printf("registered with server %s\n", registerResponse.ServerConf.Server)
}
