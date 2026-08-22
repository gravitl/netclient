package functions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// DeviceNetwork mirrors the server device API network entry.
type DeviceNetwork struct {
	NetworkID           string `json:"network_id"`
	DisplayName         string `json:"display_name,omitempty"`
	Joined              bool   `json:"joined"`
	Connected           bool   `json:"connected"`
	Pending             bool   `json:"pending"`
	Status              string `json:"status"`
	ApprovalRequired    bool   `json:"approval_required"`
	ApprovalRequestedAt *int64 `json:"approval_requested_at,omitempty"`
	JITEnabled          bool   `json:"jit_enabled"`
	JITAppliesToUser    bool   `json:"jit_applies_to_user"`
	HasJITAccess        bool   `json:"has_jit_access"`
	JITPendingRequest   bool   `json:"jit_pending_request"`
	JITExpiresAt        *int64 `json:"jit_expires_at,omitempty"`
}

// deviceSuccessResponse mirrors models.SuccessResponse JSON (capitalized keys, no tags).
type deviceSuccessResponse struct {
	Code     int
	Message  string
	Response json.RawMessage
}

func deviceServerURL() (string, error) {
	server := config.CurrServer
	if server == "" {
		return "", fmt.Errorf("server not configured")
	}
	return "https://" + strings.TrimPrefix(server, "https://"), nil
}

func deviceRequest(method, path, token string, body io.Reader) (*http.Response, error) {
	return deviceRequestWithHost(method, path, token, body, true)
}

func deviceRequestWithHost(method, path, token string, body io.Reader, includeHost bool) (*http.Response, error) {
	base, err := deviceServerURL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Application-Name", desktopAppHeader)
	if includeHost {
		req.Header.Set(deviceHostIDHeader, config.Netclient().ID.String())
	}
	if tenantID := config.Netclient().TenantID; tenantID != "" {
		req.Header.Set(scope.HeaderTenantID, tenantID)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func decodeDeviceResponse(resp *http.Response, dest any) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp models.ErrorResponse
		if json.Unmarshal(data, &errResp) == nil && errResp.Message != "" {
			return fmt.Errorf("%s", errResp.Message)
		}
		return fmt.Errorf("device api error: %s", resp.Status)
	}
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

func decodeDeviceRegisterResponse(resp *http.Response) (models.RegisterResponse, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.RegisterResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp models.ErrorResponse
		if json.Unmarshal(data, &errResp) == nil && errResp.Message != "" {
			return models.RegisterResponse{}, fmt.Errorf("%s", errResp.Message)
		}
		return models.RegisterResponse{}, fmt.Errorf("device api error: %s", resp.Status)
	}

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
	host := strings.TrimPrefix(strings.TrimSpace(server), "https://")
	if host == "" {
		return models.ServerConfig{}, fmt.Errorf("server not configured")
	}
	url := fmt.Sprintf("https://%s/api/server/getserverinfo", host)
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
	if resp.ServerConf.API == "" || resp.ServerConf.Broker == "" {
		fetched, err := fetchModelsServerConfig(server, token)
		if err != nil {
			return fmt.Errorf("failed to fetch server config: %w", err)
		}
		resp.ServerConf = fetched
	}
	canon := canonicalServerID(resp.ServerConf.API)
	if canon == "" {
		canon = canonicalServerID(server)
	}
	if canon == "" {
		return fmt.Errorf("server not configured")
	}
	resp.ServerConf.API = canon
	resp.ServerConf.Server = canon
	return nil
}

func canonicalServerID(id string) string {
	return strings.TrimPrefix(strings.TrimSpace(id), "https://")
}

// RegisterDeviceOnServer registers the host via the device REST API using a user JWT.
func RegisterDeviceOnServer(server, token string) error {
	server = strings.TrimPrefix(strings.TrimSpace(server), "https://")
	if server != "" && config.CurrServer != server {
		_ = config.SetCurrServerCtxInFile(server)
		config.CurrServer = server
	}
	host, err := prepareRegistrationHost()
	if err != nil {
		return fmt.Errorf("error when checking host values - %w", err)
	}
	body, err := json.Marshal(host)
	if err != nil {
		return err
	}
	resp, err := deviceRequest(http.MethodPost, "/api/v1/device/register", token, bytes.NewReader(body))
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
func FetchDeviceNetworks(server, token string) ([]DeviceNetwork, error) {
	return fetchDeviceNetworksImpl(server, token)
}

var fetchDeviceNetworksImpl = func(server, token string) ([]DeviceNetwork, error) {
	if server != "" && config.CurrServer != server {
		_ = config.SetCurrServerCtxInFile(server)
		config.CurrServer = server
	}
	// Include host so joined/pending/connected state is returned for this device.
	resp, err := deviceRequestWithHost(http.MethodGet, "/api/v1/device/networks", token, nil, true)
	if err != nil {
		return nil, err
	}
	var networks []DeviceNetwork
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
	var result struct {
		Status string `json:"status"`
	}
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
	body, err := json.Marshal(struct {
		Reason string `json:"reason"`
	}{Reason: reason})
	if err != nil {
		return err
	}
	path := "/api/v1/jit_user/request?network=" + url.QueryEscape(network)
	resp, err := deviceRequestWithHost(http.MethodPost, path, token, bytes.NewReader(body), false)
	if err != nil {
		return err
	}
	return decodeDeviceResponse(resp, nil)
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
