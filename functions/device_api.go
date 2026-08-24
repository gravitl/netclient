package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/gravitl/netmaker/scope"
)

const deviceHostIDHeader = "X-Host-ID"
const desktopAppHeader = "netmaker-desktop"

// ErrJITAccessRequired is returned when connect/join is blocked pending JIT approval.
var ErrJITAccessRequired = errors.New("JIT access required: please request access from network admin")

// ErrApprovalPending is returned when a join request is awaiting admin approval.
var ErrApprovalPending = errors.New("host approval pending for network")

// ErrApprovalRequired is returned when the user must request join before connecting.
var ErrApprovalRequired = errors.New("host approval required for network")

// ErrDeviceBlocked is returned when posture checks block network access.
var ErrDeviceBlocked = errors.New("access blocked: this device doesn't meet security requirements")

// deviceSuccessResponse mirrors models.SuccessResponse JSON (capitalized keys, no tags).
type deviceSuccessResponse struct {
	Code     int
	Message  string
	Response json.RawMessage
}

func deviceServerURL() (string, error) {
	srv := config.GetServer(config.CurrServer)
	api := ""
	if srv != nil {
		api = srv.API
	}
	if api == "" {
		api = config.CurrServer
	}
	api = config.NormalizeServerAPI(api)
	if api == "" {
		return "", fmt.Errorf("server not configured")
	}
	return config.APIBaseURL(api), nil
}

func deviceRequest(method, path, token string, data any) ([]byte, error) {
	return deviceRequestWithHost(method, path, token, data, true)
}

func deviceRequestWithHost(method, path, token string, data any, includeHost bool) ([]byte, error) {
	base, err := deviceServerURL()
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("X-Application-Name", desktopAppHeader)
	if includeHost {
		headers.Set(deviceHostIDHeader, config.Netclient().ID.String())
	}
	if tenantID := config.Netclient().TenantID; tenantID != "" {
		headers.Set(scope.HeaderTenantID, tenantID)
	}
	respBytes, err := ncutils.SendRequest(method, base+path, headers, data)
	if err != nil {
		return nil, err
	}
	return respBytes.Bytes(), nil
}

func decodeDeviceResponse(data []byte, dest any) error {
	if dest == nil {
		return nil
	}
	var wrapped deviceSuccessResponse
	if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Response) > 0 {
		if err := json.Unmarshal(wrapped.Response, dest); err != nil {
			logger.Log(0, "device api: failed to decode wrapped response:", err.Error())
			return err
		}
		return nil
	}
	if err := json.Unmarshal(data, dest); err != nil {
		logger.Log(0, "device api: failed to decode response:", err.Error())
		return err
	}
	return nil
}

type deviceRegisterPayload struct {
	ServerConf    models.ServerConfig `json:"server_config"`
	RequestedHost schema.Host         `json:"requested_host"`
	Host          schema.Host         `json:"host"`
}

func decodeDeviceRegisterResponse(data []byte) (models.RegisterResponse, error) {
	var payload deviceRegisterPayload
	var wrapped deviceSuccessResponse
	if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Response) > 0 {
		if err := json.Unmarshal(wrapped.Response, &payload); err != nil {
			return models.RegisterResponse{}, err
		}
	} else if err := json.Unmarshal(data, &payload); err != nil {
		return models.RegisterResponse{}, err
	}

	registerResponse := models.RegisterResponse{
		ServerConf:    payload.ServerConf,
		RequestedHost: payload.RequestedHost,
	}
	if registerResponse.RequestedHost.ID == uuid.Nil && payload.Host.ID != uuid.Nil {
		registerResponse.RequestedHost = payload.Host
	}
	return registerResponse, nil
}

func fetchModelsServerConfig(server, token string) (models.ServerConfig, error) {
	api := ""
	if srv := config.GetServer(server); srv != nil {
		api = srv.API
	}
	if api == "" {
		api = server
	}
	api = config.NormalizeServerAPI(api)
	if api == "" {
		return models.ServerConfig{}, fmt.Errorf("server not configured")
	}
	url := fmt.Sprintf("%s/api/server/getserverinfo", config.APIBaseURL(api))
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("X-Application-Name", desktopAppHeader)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
		return models.ServerConfig{}, err
	}
	var cfg models.ServerConfig
	if err := json.Unmarshal(respBytes.Bytes(), &cfg); err != nil {
		return models.ServerConfig{}, err
	}
	return cfg, nil
}

func ensureRegisterServerConf(resp *models.RegisterResponse, server, token string) error {
	if resp == nil {
		return fmt.Errorf("empty register response")
	}
	domain := config.NormalizeServerHost(server)
	if domain == "" {
		domain = config.NormalizeServerHost(resp.ServerConf.API)
	}
	if domain == "" {
		domain = config.NormalizeServerHost(resp.ServerConf.Server)
	}
	if domain == "" {
		return fmt.Errorf("server not configured")
	}

	preservedAPI := ""
	if existing := config.GetServer(domain); existing != nil && existing.API != "" {
		preservedAPI = config.NormalizeServerAPI(existing.API)
	}

	if resp.ServerConf.API == "" || resp.ServerConf.Broker == "" {
		fetched, err := fetchModelsServerConfig(domain, token)
		if err != nil {
			return fmt.Errorf("failed to fetch server config: %w", err)
		}
		if resp.ServerConf.Broker == "" {
			resp.ServerConf.Broker = fetched.Broker
		}
		if resp.ServerConf.API == "" {
			resp.ServerConf.API = fetched.API
		}
		// Keep other useful fields if missing.
		if resp.ServerConf.Server == "" {
			resp.ServerConf.Server = fetched.Server
		}
	}

	api := preservedAPI
	if api == "" {
		api = config.NormalizeServerAPI(resp.ServerConf.API)
	}
	if api == "" {
		api = config.NormalizeServerAPI(domain)
	}
	resp.ServerConf.API = api
	resp.ServerConf.Server = domain
	return nil
}

func canonicalServerID(id string) string {
	return config.NormalizeServerHost(id)
}

// RegisterDeviceOnServer registers the host via the device REST API using a user JWT.
func RegisterDeviceOnServer(server, token string) error {
	server = config.NormalizeServerHost(server)
	if server != "" && config.CurrServer != server {
		_ = config.SetCurrServerCtxInFile(server)
		config.CurrServer = server
	}
	host, err := prepareRegistrationHost()
	if err != nil {
		return fmt.Errorf("error when checking host values - %w", err)
	}
	resp, err := deviceRequest(http.MethodPost, "/api/v1/device/register", token, host)
	if err != nil {
		return err
	}
	registerResponse, err := decodeDeviceRegisterResponse(resp)
	if err != nil {
		return err
	}
	if err := ensureRegisterServerConf(&registerResponse, server, token); err != nil {
		return err
	}
	config.CurrServer = registerResponse.ServerConf.Server
	_ = config.SetCurrServerCtxInFile(config.CurrServer)
	handleRegisterResponse(&registerResponse)
	return nil
}

// FetchDeviceNetworks returns networks visible to the user from the server device API.
func FetchDeviceNetworks(server, token string) ([]models.DeviceNetwork, error) {
	return fetchDeviceNetworksImpl(server, token)
}

var fetchDeviceNetworksImpl = func(server, token string) ([]models.DeviceNetwork, error) {
	if server != "" && config.CurrServer != server {
		_ = config.SetCurrServerCtxInFile(server)
		config.CurrServer = server
	}
	// Include host so joined/pending/connected state is returned for this device.
	resp, err := deviceRequestWithHost(http.MethodGet, "/api/v1/device/networks", token, nil, true)
	if err != nil {
		return nil, err
	}
	var networks []models.DeviceNetwork
	if err := decodeDeviceResponse(resp, &networks); err != nil {
		return nil, err
	}
	return networks, nil
}

// JoinDeviceNetworkOnServer registers the host on a network via the device API.
// Returns join status: "joined".
func JoinDeviceNetworkOnServer(network, token string) (string, error) {
	resp, err := deviceRequest(http.MethodPost, "/api/v1/device/networks/"+network+"/join", token, nil)
	if err != nil {
		return "", err
	}
	var result models.DeviceJoinResult
	if err := decodeDeviceResponse(resp, &result); err != nil {
		return "", err
	}
	if result.Status == "" {
		return "joined", nil
	}
	return result.Status, nil
}

// LeaveDeviceNetworkOnServer removes the host from a network via the device API.
func LeaveDeviceNetworkOnServer(network, token string) error {
	resp, err := deviceRequest(http.MethodDelete, "/api/v1/device/networks/"+network+"/leave", token, nil)
	if err != nil {
		return err
	}
	return decodeDeviceResponse(resp, nil)
}

// CancelDeviceNetworkJoinOnServer cancels a pending join approval request.
func CancelDeviceNetworkJoinOnServer(network, token string) error {
	resp, err := deviceRequest(http.MethodDelete, "/api/v1/device/networks/"+network+"/cancel", token, nil)
	if err != nil {
		return err
	}
	return decodeDeviceResponse(resp, nil)
}

// RequestJITOnServer submits a JIT access request via the server user JIT API.
func RequestJITOnServer(network, token, reason string) error {
	path := "/api/v1/jit_user/request?network=" + url.QueryEscape(network)
	_, err := deviceRequestWithHost(http.MethodPost, path, token, struct {
		Reason string `json:"reason"`
	}{Reason: reason}, false)
	return err
}

// SyncDeviceWithServer pulls local config and optionally nudges server sync.
func SyncDeviceWithServer(token string) error {
	resp, err := deviceRequest(http.MethodPost, "/api/v1/device/sync", token, nil)
	if err == nil {
		_ = decodeDeviceResponse(resp, nil)
	}
	_, _, _, err = PullForDesktop(false, true)
	return err
}

// ListDeviceExitNodes returns internet egress exit nodes available to this device on the network.
func ListDeviceExitNodes(network, token string) ([]models.DeviceExitNode, error) {
	if network == "" {
		return nil, fmt.Errorf("network is required")
	}
	path := "/api/v1/device/networks/" + url.PathEscape(network) + "/exit_nodes"
	resp, err := deviceRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return nil, err
	}
	var nodes []models.DeviceExitNode
	if err := decodeDeviceResponse(resp, &nodes); err != nil {
		return nil, err
	}
	if nodes == nil {
		nodes = []models.DeviceExitNode{}
	}
	attachExitNodeLatencies(network, nodes)
	return nodes, nil
}

// GetDeviceSelectedExitNode returns the currently selected exit node, or nil if none.
func GetDeviceSelectedExitNode(network, token string) (*models.DeviceExitNode, error) {
	if network == "" {
		return nil, fmt.Errorf("network is required")
	}
	path := "/api/v1/device/networks/" + url.PathEscape(network) + "/exit_node"
	resp, err := deviceRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return nil, err
	}
	var node models.DeviceExitNode
	if err := decodeDeviceResponse(resp, &node); err != nil {
		return nil, err
	}
	if node.EgressID == "" {
		return nil, nil
	}
	nodes := []models.DeviceExitNode{node}
	attachExitNodeLatencies(network, nodes)
	return &nodes[0], nil
}

// SelectDeviceExitNode selects or clears (empty egressID) the exit node for the device.
// Switching A→B is not done in one step: clear first (None), then assign. The server
// rejects a direct switch while RelayedBy still points at the current gateway.
func SelectDeviceExitNode(network, token, egressID string) (*models.DeviceExitNode, error) {
	if network == "" {
		return nil, fmt.Errorf("network is required")
	}
	resp, err := putDeviceExitNode(network, token, egressID)
	if err != nil {
		return nil, err
	}
	var node models.DeviceExitNode
	if err := decodeDeviceResponse(resp, &node); err != nil {
		return nil, err
	}
	wantGW := egressID != "" && node.EgressID != ""
	// Wait for routing to apply so a later select is not blocked by RelayedBy.
	pullAndApplyExitNodeChange(network, wantGW)
	if !wantGW {
		return nil, nil
	}
	nodes := []models.DeviceExitNode{node}
	attachExitNodeLatencies(network, nodes)
	return &nodes[0], nil
}

func putDeviceExitNode(network, token, egressID string) ([]byte, error) {
	path := "/api/v1/device/networks/" + url.PathEscape(network) + "/exit_node"
	return deviceRequest(http.MethodPut, path, token, models.DeviceExitNodeSelectionReq{
		EgressID: egressID,
	})
}

// ConnectNetwork joins (if needed) then connects locally.
func ConnectNetwork(network, server, token string) error {
	if token != "" {
		if err := checkDeviceNetworkAccess(network, server, token); err != nil {
			return err
		}
	}
	nodes := config.GetNodes()
	if _, ok := nodes[network]; !ok {
		if token == "" {
			return fmt.Errorf("network %s is not joined", network)
		}
		status, err := JoinDeviceNetworkOnServer(network, token)
		if err != nil {
			return err
		}
		if status != "joined" && status != "" {
			return fmt.Errorf("unexpected join status: %s", status)
		}
		if _, _, _, err := PullForDesktop(false, true); err != nil {
			return fmt.Errorf("failed to sync after join: %w", err)
		}
	}
	return Connect(network)
}

func checkDeviceNetworkAccess(network, server, token string) error {
	nets, err := FetchDeviceNetworks(server, token)
	if err != nil {
		return err
	}
	for _, n := range nets {
		if n.NetworkID != network {
			continue
		}
		if n.Status == "blocked" {
			return ErrDeviceBlocked
		}
		if n.Status == "jit_required" || (n.JITAppliesToUser && !n.HasJITAccess) {
			return ErrJITAccessRequired
		}
		return nil
	}
	return nil
}
