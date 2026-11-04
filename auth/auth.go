// Package auth provides netclient auth logic with server
package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/scope"
)

// DeviceHostIDHeader identifies the local host when authenticating with a user JWT.
const DeviceHostIDHeader = "X-Host-ID"

// ErrUserSessionRequired is returned for user-owned devices when Desktop has no
// active user JWT. Host-password auth is not allowed for those devices.
var ErrUserSessionRequired = errors.New("user session required for this device")

var (
	jwtToken     string
	jwtSecretKey []byte

	// UserTokenProvider returns the active Desktop user JWT, or empty when
	// logged out. Wired from the desktop package to avoid an import cycle.
	UserTokenProvider func() string

	// pendingUserToken covers the login window before uiapi.setSession runs:
	// RegisterSession pulls while the request JWT is not yet in session state.
	pendingUserMu    sync.RWMutex
	pendingUserToken string
)

// SetPendingUserToken temporarily exposes a user JWT to Authenticate (login pull).
// Pass empty to clear.
func SetPendingUserToken(token string) {
	pendingUserMu.Lock()
	pendingUserToken = strings.TrimSpace(token)
	pendingUserMu.Unlock()
}

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

// AuthenticateOptions controls host authentication behavior.
type AuthenticateOptions struct {
	// CleanupOnUnauthorized removes local server registration on HTTP 401.
	// Desktop UI flows should set this false to avoid wiping servers.json on re-login.
	CleanupOnUnauthorized bool
}

// Authenticate authenticates with netmaker api to permit subsequent interactions with the api
func Authenticate(server *config.Server, host *config.Config) (string, error) {
	return AuthenticateWithOptions(server, host, AuthenticateOptions{CleanupOnUnauthorized: true})
}

// AuthenticateOnce is a single short attempt. Interactive disconnect uses it
// when the cached host JWT is missing, so a blackholed API cannot add another
// full retry budget before the node update itself.
func AuthenticateOnce(server *config.Server, host *config.Config, timeout time.Duration) (string, error) {
	return authenticate(server, host, AuthenticateOptions{CleanupOnUnauthorized: true}, timeout)
}

// AuthenticateWithOptions authenticates with optional control over 401 cleanup behavior.
func AuthenticateWithOptions(server *config.Server, host *config.Config, opts AuthenticateOptions) (string, error) {
	return authenticate(server, host, opts, 0)
}

// IsUserOwnedDevice reports whether this host is bound to a Netmaker user
// (desktop/device registration).
func IsUserOwnedDevice(host *config.Config) bool {
	if host != nil {
		return strings.TrimSpace(host.OwnerUsername) != ""
	}
	return config.IsUserOwnedDevice()
}

// ApplyAPIHeaders sets Authorization. X-Host-ID is always included when a host
// is known so user-JWT AuthorizeHost can bind the request to this device.
func ApplyAPIHeaders(headers http.Header, token string, host *config.Config) {
	if headers == nil {
		return
	}
	headers.Set("Authorization", "Bearer "+token)
	if host != nil && host.ID != uuid.Nil {
		headers.Set(DeviceHostIDHeader, host.ID.String())
	}
}

// IsMissingHostError reports host authenticate failures where the server no
// longer has this device (deleted host, leftover enrollment after reinstall).
// The API returns HTTP 400 with "record not found", not 401.
func IsMissingHostError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "record not found") {
		return true
	}
	return strings.Contains(msg, "failed to authenticate") && strings.Contains(msg, "400")
}

func userSessionToken() string {
	pendingUserMu.RLock()
	pending := pendingUserToken
	pendingUserMu.RUnlock()
	if pending != "" {
		return pending
	}
	if UserTokenProvider == nil {
		return ""
	}
	return strings.TrimSpace(UserTokenProvider())
}

func authenticate(server *config.Server, host *config.Config, opts AuthenticateOptions, timeout time.Duration) (string, error) {
	owner := ""
	tenant := ""
	hostID := ""
	hostPassSet := false
	if host != nil {
		owner = strings.TrimSpace(host.OwnerUsername)
		tenant = strings.TrimSpace(host.TenantID)
		hostID = host.ID.String()
		hostPassSet = strings.TrimSpace(host.HostPass) != ""
	}
	serverName := ""
	if server != nil {
		serverName = server.Name
	}

	// User-owned desktop devices must use the Desktop user JWT. HostPass must
	// not mint a control-plane token after logout or for a different user.
	if IsUserOwnedDevice(host) {
		if tok := userSessionToken(); tok != "" {
			fmt.Println("auth debug: mode=user_jwt owner_set=true",
				"owner=", owner, "tenant=", tenant, "host=", hostID, "server=", serverName)
			return tok, nil
		}
		fmt.Println("auth debug: mode=no_session owner_set=true",
			"owner=", owner, "tenant=", tenant, "host=", hostID, "server=", serverName)
		return "", ErrUserSessionRequired
	}

	if jwtToken != "" && !isTokenExpired(jwtToken) {
		fmt.Println("auth debug: mode=cached_host_jwt owner_set=false",
			"tenant=", tenant, "host=", hostID, "server=", serverName, "hostpass_set=", hostPassSet)
		return jwtToken, nil
	}
	apiHost := ""
	if server != nil {
		apiHost = config.NormalizeServerAPI(server.API)
	}
	fmt.Println("auth debug: mode=host_pass owner_set=false",
		"tenant=", tenant, "host=", hostID, "server=", serverName, "hostpass_set=", hostPassSet,
		"api=", apiHost)
	data := models.AuthParams{
		MacAddress: host.MacAddress.String(),
		ID:         host.ID.String(),
		Password:   host.HostPass,
	}

	url := fmt.Sprintf("%s/api/hosts/adm/authenticate", config.APIBaseURL(config.NormalizeServerAPI(server.API)))
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set(scope.HeaderTenantID, host.TenantID)
	var respBytes *bytes.Buffer
	var err error
	if timeout > 0 {
		respBytes, err = ncutils.SendRequestOnce(http.MethodPost, url, headers, data, timeout)
	} else {
		respBytes, err = ncutils.SendRequest(http.MethodPost, url, headers, data)
	}
	if err != nil {
		var notOkErr ncutils.ErrStatusNotOk
		if errors.As(err, &notOkErr) {
			if notOkErr.Status == http.StatusUnauthorized {
				fmt.Println("auth debug: host_pass 401",
					"status=", notOkErr.Status, "server_msg=", notOkErr.Message,
					"tenant=", tenant, "host=", hostID, "cleanup=", opts.CleanupOnUnauthorized)
				if opts.CleanupOnUnauthorized {
					if err := cleanUpByServer(server); err != nil {
						return "", err
					}
					return "", fmt.Errorf("unauthorized request - removed instances for %s", server.Name)
				}
				return "", fmt.Errorf("host authentication failed: unauthorized")
			}

			fmt.Println("auth debug: host_pass failed",
				"status=", notOkErr.Status, "server_msg=", notOkErr.Message,
				"tenant=", tenant, "host=", hostID)
			return "", fmt.Errorf("failed to authenticate %d %s", notOkErr.Status, notOkErr.Message)
		}

		fmt.Println("auth debug: host_pass request error", "err=", err, "tenant=", tenant, "host=", hostID)
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
	if config.CurrServer == server.Name {
		config.SwitchToRemainingServer()
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
	}
	_ = daemon.Restart()
	return nil
}
