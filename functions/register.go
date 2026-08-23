package functions

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/posture"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/scope"
)

// Register - should be simple to register with a token
func Register(token string) error {
	data, err := b64.StdEncoding.DecodeString(token)
	if err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	var serverData models.EnrollmentToken
	if err = json.Unmarshal(data, &serverData); err != nil {
		logger.FatalLog("could not read enrollment token")
	}
	if existing := config.GetServerByAPIHost(serverData.Server); existing != nil &&
		existing.TenantID != "" && existing.TenantID != serverData.TenantID {
		return fmt.Errorf("already joined to server %s under a different tenant; run `netclient server leave %s` before joining a different tenant on it", existing.Name, existing.Name)
	}
	host := config.Netclient()
	ip, err := ncutils.GetInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			host.Interfaces = ip
		}
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else if defaultInterface != ncutils.GetInterfaceName() {
		host.DefaultInterface = defaultInterface
	}
	shouldUpdateHost, err := doubleCheck(host)
	if err != nil {
		logger.FatalLog(fmt.Sprintf("error when checking host values - %v", err.Error()))
	}
	if shouldUpdateHost { // get most up to date values before submitting to server
		host = config.Netclient()
	}

	url := fmt.Sprintf("https://%s/api/v1/host/register/%s", serverData.Server, token)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set(scope.HeaderTenantID, serverData.TenantID)
	posture.ApplyIdentity(&host.Host)
	respBytes, err := ncutils.SendRequest(http.MethodPost, url, headers, host)
	if err != nil {
		if denyErr := auth.AsMDMDenied(err); errors.Is(denyErr, auth.ErrMDMDenied) {
			fmt.Fprintln(os.Stderr, MDMDeniedMessage)
			logger.Log(0, "registration refused by server on MDM grounds")
			os.Exit(2)
		}
		logger.FatalLog("error registering with server", err.Error())
		return err
	}

	var registerResponse models.RegisterResponse
	err = json.Unmarshal(respBytes.Bytes(), &registerResponse)
	if err != nil {
		return err
	}

	if config.CurrServer != "" && config.CurrServer != registerResponse.ServerConf.Server {
		fmt.Println("WARNING: Joining any network on another server will disconnect netclient from the networks of the current server ->", config.CurrServer)
	}

	handleRegisterResponse(&registerResponse)
	return nil
}

func doubleCheck(host *config.Config) (shouldUpdate bool, err error) {
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

	if shouldUpdateHost {
		config.UpdateNetclient(*host)
		config.WriteNetclientConfig()
		return true, nil
	}
	return
}

func handleRegisterResponse(registerResponse *models.RegisterResponse) {
	if registerResponse == nil {
		return
	}
	// Identity is bare domain; API stays host:port for HTTPS.
	serverKey := canonicalServerID(registerResponse.ServerConf.Server)
	if serverKey == "" {
		serverKey = canonicalServerID(registerResponse.ServerConf.API)
	}
	if serverKey == "" {
		serverKey = canonicalServerID(config.CurrServer)
	}
	if serverKey == "" {
		logger.Log(0, "register response missing server identity")
		return
	}

	preservedAPI := ""
	if existing := config.GetServer(serverKey); existing != nil && existing.API != "" {
		preservedAPI = config.NormalizeServerAPI(existing.API)
	}
	api := preservedAPI
	if api == "" {
		api = config.NormalizeServerAPI(registerResponse.ServerConf.API)
	}
	if api == "" {
		api = config.NormalizeServerAPI(serverKey)
	}
	registerResponse.ServerConf.API = api
	registerResponse.ServerConf.Server = serverKey

	config.CurrServer = serverKey
	config.UpdateServerConfig(&registerResponse.ServerConf)
	server := config.GetServer(serverKey)
	if server == nil {
		logger.Log(0, "failed to save server: config not updated")
		return
	}
	if err := config.SaveServer(serverKey, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	config.UpdateHost(&registerResponse.RequestedHost)
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "failed to save netclient config after register", err.Error())
	}
	if err := config.SetCurrServerCtxInFile(serverKey); err != nil {
		logger.Log(0, "failed to save server context", err.Error())
	}
	UpdateHostFromServer(&registerResponse.RequestedHost)
	if err := daemon.Restart(); err != nil {
		logger.Log(3, "daemon restart failed:", err.Error())
	}
	fmt.Printf("registered with server %s\n", serverKey)
}
