package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/uiapi"
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
	networks, err := fetchDeviceNetworksImpl(server, token)
	if err != nil {
		return nil, err
	}
	enforceAutoExitForConnected(networks, token)
	return networks, nil
}

var autoExitEnforced sync.Map

// networkAutoSelectExit reports whether the server requires auto exit selection.
// Tests replace this.
var networkAutoSelectExit = func(network, server, token string) (bool, error) {
	networks, err := fetchDeviceNetworksImpl(server, token)
	if err != nil {
		return false, err
	}
	for _, n := range networks {
		if n.NetworkID == network {
			return n.AutoSelectExitNode, nil
		}
	}
	return false, nil
}

// selectNearestExitNode selects the nearest exit. Tests replace this.
var selectNearestExitNode = SelectNearestDeviceExitNode

// NetworkRequiresAutoExit reports whether the network forces auto exit selection.
func NetworkRequiresAutoExit(network, server, token string) (bool, error) {
	if strings.TrimSpace(token) == "" || network == "" {
		return false, nil
	}
	return networkAutoSelectExit(network, server, token)
}

// applyEnforcedAutoExit selects the nearest exit before a connect is published
// when the network requires it. Missing exits do not fail the connect.
// Always arms local auto_exit desired state so IGW failover can switch exits.
func applyEnforcedAutoExit(network, token string) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	required, err := networkAutoSelectExit(network, config.CurrServer, token)
	if err != nil || !required {
		return err
	}
	node, err := selectNearestExitNode(network, token)
	if err != nil {
		// Still arm auto mode so a later reconcile/failover can pick one up.
		armEnforcedAutoExitDesired(network, "")
		return err
	}
	egressID := ""
	if node != nil {
		egressID = node.EgressID
	}
	armEnforcedAutoExitDesired(network, egressID)
	autoExitEnforced.Store(network, struct{}{})
	return nil
}

func armEnforcedAutoExitDesired(network, egressID string) {
	user, tenant, ok := desktopSessionIdentity()
	if !ok {
		return
	}
	egressID = strings.TrimSpace(egressID)
	if egressID == "" {
		egressID = strings.TrimSpace(config.GetDesiredEgressID(user, tenant))
	}
	_ = config.SetDesiredAutoExitNode(user, tenant, network, egressID)
}

// applyDeferredAutoExitAfterConnect selects nearest when Auto was chosen while
// disconnected (or enforced pick failed before the overlay was up).
func applyDeferredAutoExitAfterConnect(network, token string) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(network) == "" {
		return
	}
	user, tenant, ok := desktopSessionIdentity()
	if !ok || !config.GetDesiredAutoExit(user, tenant) {
		return
	}
	exitNet := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
	if exitNet != "" && exitNet != network {
		return
	}
	if other := uiapi.ActiveExitNetwork(network); other != "" {
		return
	}
	if cur, err := GetDeviceSelectedExitNode(network, token); err == nil && cur != nil && strings.TrimSpace(cur.EgressID) != "" {
		_ = config.SetDesiredAutoExitNode(user, tenant, network, cur.EgressID)
		return
	}
	node, err := selectNearestExitNode(network, token)
	if err != nil {
		slog.Warn("deferred auto exit select after connect failed", "network", network, "error", err)
		return
	}
	if node != nil {
		_ = config.SetDesiredAutoExitNode(user, tenant, network, node.EgressID)
	}
}

func enforceAutoExitForConnected(networks []models.DeviceNetwork, token string) {
	if strings.TrimSpace(token) == "" {
		return
	}
	nodes := config.GetNodes()
	for _, n := range networks {
		if !n.AutoSelectExitNode {
			autoExitEnforced.Delete(n.NetworkID)
			continue
		}
		node, ok := nodes[n.NetworkID]
		if !ok || !node.Connected {
			continue
		}
		// Always arm local AUTO so failover works even when the server already
		// assigned an exit (EnsureAutoExitNode) without a client select.
		armEnforcedAutoExitDesired(n.NetworkID, "")
		if _, done := autoExitEnforced.Load(n.NetworkID); done {
			continue
		}
		if uiapi.ActiveExitNetwork(n.NetworkID) != "" {
			autoExitEnforced.Store(n.NetworkID, struct{}{})
			continue
		}
		autoExitEnforced.Store(n.NetworkID, struct{}{})
		picked, err := selectNearestExitNode(n.NetworkID, token)
		if err != nil {
			autoExitEnforced.Delete(n.NetworkID)
			slog.Warn("auto exit select for connected network failed", "network", n.NetworkID, "error", err)
			continue
		}
		if picked != nil {
			armEnforcedAutoExitDesired(n.NetworkID, picked.EgressID)
		}
	}
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
		// Device approval answers with 202 and "host approval pending". That is
		// the request succeeding, not a failed join.
		var statusErr ncutils.ErrStatusNotOk
		if errors.As(err, &statusErr) && statusErr.Status == http.StatusAccepted {
			return models.DeviceJoinStatusPending, nil
		}
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
	_, _, _, err = Pull(false, true, false)
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
// Peer/IGW routes are applied by the MQTT peer update; we do not pull here.
func SelectDeviceExitNode(network, token, egressID string) (*models.DeviceExitNode, error) {
	if network == "" {
		return nil, fmt.Errorf("network is required")
	}
	user, tenant := uiapi.SessionIdentity()
	egressID = strings.TrimSpace(egressID)

	// Persist desired intent BEFORE the server PUT. MQTT peer updates can arrive
	// immediately; if want_igw is still false a ChangeDefaultGw=false update will
	// RestoreInternetGw and wipe CurrGw/DNS right after SetInternetGw.
	if egressID == "" {
		_ = config.ClearDesiredExitNode(user, tenant)
	} else {
		_ = config.SetDesiredExitNode(user, tenant, network, egressID)
	}

	resp, err := putDeviceExitNode(network, token, egressID, false)
	if err != nil {
		if egressID != "" {
			_ = config.ClearDesiredExitNode(user, tenant)
		}
		return nil, err
	}
	var node models.DeviceExitNode
	if err := decodeDeviceResponse(resp, &node); err != nil {
		if egressID != "" {
			_ = config.ClearDesiredExitNode(user, tenant)
		}
		return nil, err
	}
	wantGW := egressID != "" && node.EgressID != ""
	if !wantGW {
		_ = config.ClearDesiredExitNode(user, tenant)
		// Restore LAN routes and OS DNS immediately; MQTT will converge peers next.
		restoreInternetGwAndDNS()
		return nil, nil
	}
	_ = config.SetDesiredExitNode(user, tenant, network, node.EgressID)
	return &node, nil
}

func networkLocallyConnected(network string) bool {
	if network == "" {
		return false
	}
	node, ok := config.GetNodes()[network]
	return ok && node.Connected
}

// SelectNearestDeviceExitNode lists exits, picks the nearest available one, and selects it.
// Persists auto_exit so session restore re-picks nearest rather than a fixed egress id.
// Switching A→B clears the current selection first (server rejects direct switch).
func SelectNearestDeviceExitNode(network, token string) (*models.DeviceExitNode, error) {
	if network == "" {
		return nil, fmt.Errorf("network is required")
	}
	nodes, err := ListDeviceExitNodes(network, token)
	if err != nil {
		return nil, err
	}
	return selectNearestDeviceExitNodeExcluding(network, token, nodes, nil)
}

// selectNearestDeviceExitNodeExcluding picks the nearest exit not in exclude and
// selects it (clear-first when switching). Callers that already listed nodes
// pass them in; otherwise pass nil to list.
//
// Never ClearDesiredExitNode here: that drops auto_exit/want_igw and races with
// peer updates / reconcile into "manual + dead exit + ISP routing".
func selectNearestDeviceExitNodeExcluding(network, token string, nodes []models.DeviceExitNode, exclude map[string]struct{}) (*models.DeviceExitNode, error) {
	var err error
	if nodes == nil {
		nodes, err = ListDeviceExitNodes(network, token)
		if err != nil {
			return nil, err
		}
	}
	pick, ok := pickNearestAvailableExitNode(nodes, exclude)
	if !ok || strings.TrimSpace(pick.EgressID) == "" {
		// While disconnected, overlay probes mark every exit unhealthy. Persist
		// Auto intent so connect/restore can pick nearest once the mesh is up.
		if !networkLocallyConnected(network) {
			user, tenant := uiapi.SessionIdentity()
			if err := config.SetDesiredAutoExitNode(user, tenant, network, ""); err != nil {
				return nil, err
			}
			slog.Info("auto exit deferred until network is connected", "network", network)
			return nil, nil
		}
		return nil, fmt.Errorf("no available exit nodes on network %s", network)
	}
	user, tenant := uiapi.SessionIdentity()
	prevEgress := strings.TrimSpace(config.GetDesiredEgressID(user, tenant))
	prevNetwork := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
	if prevNetwork == "" {
		prevNetwork = network
	}
	restoreAutoDesired := func() {
		_ = config.SetDesiredAutoExitNode(user, tenant, prevNetwork, prevEgress)
	}

	// Keep auto intent for the whole clear→assign window so MQTT/reconcile do
	// not treat this as a manual fixed egress (or as exit-off).
	_ = config.SetDesiredAutoExitNode(user, tenant, network, pick.EgressID)

	current, err := GetDeviceSelectedExitNode(network, token)
	if err != nil {
		slog.Warn("failed to read current exit before auto-select", "network", network, "error", err)
	}
	if current != nil && strings.TrimSpace(current.EgressID) != "" && current.EgressID != pick.EgressID {
		// force=true bypasses auto_select_exit_node's ban on clearing so the
		// usual clear→assign switch can drop RelayedBy before selecting B.
		if _, err := putDeviceExitNode(network, token, "", true); err != nil {
			restoreAutoDesired()
			return nil, err
		}
	}
	if current == nil || current.EgressID != pick.EgressID {
		resp, err := putDeviceExitNode(network, token, pick.EgressID, false)
		if err != nil {
			restoreAutoDesired()
			return nil, err
		}
		var node models.DeviceExitNode
		if err := decodeDeviceResponse(resp, &node); err != nil {
			restoreAutoDesired()
			return nil, err
		}
		if node.EgressID == "" {
			restoreAutoDesired()
			return nil, fmt.Errorf("server did not select exit node %s", pick.EgressID)
		}
		pick = node
	}
	_ = config.SetDesiredAutoExitNode(user, tenant, network, pick.EgressID)
	return &pick, nil
}

// DropNetworkExitSelection clears the server exit on one network and leaves the
// saved exit for any other network in place.
func DropNetworkExitSelection(network, token string) error {
	if strings.TrimSpace(network) == "" || strings.TrimSpace(token) == "" {
		return nil
	}
	_, err := putDeviceExitNode(network, token, "", false)
	return err
}

func putDeviceExitNode(network, token, egressID string, force bool) ([]byte, error) {
	path := "/api/v1/device/networks/" + url.PathEscape(network) + "/exit_node"
	return deviceRequest(http.MethodPut, path, token, models.DeviceExitNodeSelectionReq{
		EgressID: egressID,
		Force:    force,
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
		if _, _, _, err := Pull(false, true, false); err != nil {
			return fmt.Errorf("failed to sync after join: %w", err)
		}
	}
	if err := Connect(network); err != nil {
		if err.Error() == "node already connected" {
			return nil
		}
		return err
	}
	return nil
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
