package uiapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
)

func checkHealth(w http.ResponseWriter, r *http.Request) {
	status := DaemonStatusOK
	wgUtil := WGQuick
	if runtime.GOOS == "windows" {
		wgUtil = WireGuardExecutable
	}
	installed := true
	if _, err := exec.LookPath(string(wgUtil)); err != nil {
		status = DaemonStatusMissingDependencies
		installed = false
	}
	resp := DaemonHealthStatus{
		Status:                   status,
		CurrentVersion:           config.Version,
		LatestVersion:            config.Version,
		OS:                       runtime.GOOS,
		Arch:                     runtime.GOARCH,
		WireGuardUtil:            wgUtil,
		IsWireGuardUtilInstalled: installed,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func configureServer(w http.ResponseWriter, r *http.Request) {
	var req SetServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondConfigureServerError(w, "invalid request body")
		return
	}
	// Name / map key = base domain (nm...); API keeps api.<domain>:port for HTTPS.
	domain := config.NormalizeServerHost(req.Server)
	domain = strings.TrimPrefix(domain, "api.")
	api := config.NormalizeServerAPI(req.Server)
	rawHost := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(req.Server), "https://"), "http://")
	if i := strings.Index(rawHost, "/"); i >= 0 {
		rawHost = rawHost[:i]
	}
	if h, _, err := net.SplitHostPort(rawHost); err == nil {
		rawHost = h
	}
	if domain == "" {
		if err := releaseSessionForServerChange("clear server"); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		config.CurrServer = ""
		if err := config.SetCurrServerCtxInFile(""); err != nil {
			uiLog(0, "uiapi: failed to clear server context:", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		uiLog(0, "uiapi: server context cleared")
		w.WriteHeader(http.StatusOK)
		return
	}
	// Self-hosted: API host is api.<SERVER_NAME>. Skip for tenant IDs (no dots).
	if strings.Contains(domain, ".") && !strings.HasPrefix(rawHost, "api.") {
		api = config.NormalizeServerAPI("api." + domain)
	}
	if api == "" {
		respondConfigureServerError(w, "invalid server")
		return
	}
	if key := config.ResolveServerKey(domain); key != "" {
		domain = strings.TrimPrefix(config.NormalizeServerHost(key), "api.")
	}
	if isServerSet(domain) {
		// Refresh API endpoint even when domain is already selected.
		_ = config.UpsertPartialServer(domain, api)
		w.WriteHeader(http.StatusOK)
		return
	}
	// Desktop may show Login while the daemon still has a JWT (logout/GUI desync).
	// Release that session instead of forcing a manual logout dance.
	if err := releaseSessionForServerChange("change server to " + domain); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	config.CurrServer = domain
	if err := config.SetCurrServerCtxInFile(domain); err != nil {
		uiLog(0, "uiapi: failed to persist server context:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	if err := config.UpsertPartialServer(domain, api); err != nil {
		uiLog(0, "uiapi: failed to persist server API:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	uiLog(0, fmt.Sprintf("uiapi: server set to %s (api %s)", domain, api))
	w.WriteHeader(http.StatusOK)
}

func respondConfigureServerError(w http.ResponseWriter, message string) {
	uiLog(0, "uiapi: POST /server rejected:", message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

// releaseSessionForServerChange drops an active UI session so POST /server can
// proceed when the Desktop login/settings UI is out of sync with the daemon.
func releaseSessionForServerChange(reason string) error {
	if !isSessionActive() {
		return nil
	}
	uiLog(0, "uiapi: releasing session before", reason)
	setStatus(Closing)
	if err := releaseSessionFn(false); err != nil {
		uiLog(1, "uiapi: error releasing session before server change:", err.Error())
	}
	if err := clearSession(false); err != nil {
		uiLog(0, "uiapi: error clearing session before server change:", err.Error())
		setStatus(Idle)
		return err
	}
	setStatus(Idle)
	return nil
}

func getServer(w http.ResponseWriter, r *http.Request) {
	writeCurrentServerResponse(w)
}

// getSession returns the current UI session and configured server details
// (same payload as GET /server). Desktop should use APIHost for Netmaker HTTP.
func getSession(w http.ResponseWriter, r *http.Request) {
	writeCurrentServerResponse(w)
}

func writeCurrentServerResponse(w http.ResponseWriter) {
	server, username, authToken := sessionToken()
	if server == "" {
		server = getCurrServerName()
	}
	resp := GetServerResponse{
		Status:     getStatus(),
		Server:     server,
		API:        currentServerAPI(server),
		APIHost:    currentServerAPIHost(server),
		Username:   username,
		AuthToken:  authToken,
		TenantID:   sessionTenantID(),
		Registered: isRegistered(server),
	}
	if isSessionActive() {
		resp.ServerConfig = serverConfig()
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		uiLog(0, "uiapi: failed to encode server/session response:", err.Error())
	}
}

// currentServerAPI returns the API host:port from servers.json (Server.API).
// Prefer servers.json; if missing for a self-hosted domain, return api.<server>.
func currentServerAPI(server string) string {
	if server == "" {
		server = getCurrServerName()
	}
	if api := configuredServerAPI(server); api != "" {
		return api
	}
	// Tenant IDs have no dots — leave empty so Desktop uses SaaS URL templates.
	base := strings.TrimPrefix(strings.TrimSpace(server), "api.")
	if base == "" || !strings.Contains(base, ".") {
		return ""
	}
	return config.NormalizeServerAPI("api." + base)
}

// currentServerAPIHost returns servers.json Server.APIHost for Desktop HTTP.
func currentServerAPIHost(server string) string {
	if server == "" {
		server = getCurrServerName()
	}
	srv := config.GetServer(server)
	if srv == nil {
		return ""
	}
	host := strings.TrimSpace(srv.APIHost)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// configuredServerAPI returns servers.json API (host:port) for the current server context.
func configuredServerAPI(server string) string {
	if server == "" {
		server = getCurrServerName()
	}
	if srv := config.GetServer(server); srv != nil && strings.TrimSpace(srv.API) != "" {
		return config.NormalizeServerAPI(srv.API)
	}
	return ""
}

func configureSession(w http.ResponseWriter, r *http.Request) {
	var req ConfigureSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.AuthToken = strings.TrimSpace(req.AuthToken)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.Username == "" || req.AuthToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !isServerSet("") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server := configuredServer()
	setStatus(Loading)
	defer func() {
		if getStatus() == Loading {
			setStatus(Running)
		}
	}()

	_, prevUser, _ := sessionToken()
	prevTenant := sessionTenantID()
	if prevUser != "" && (prevUser != req.Username || prevTenant != req.TenantID) {
		if err := releaseSessionFn(false); err != nil {
			uiLog(1, "uiapi: failed to disconnect prior session before handoff:", err.Error())
		}
	}

	if err := registerSession(server, req.Username, req.AuthToken, req.Password, req.TenantID); err != nil {
		uiLog(0, "uiapi: PUT /session register failed:", err.Error())
		setStatus(Idle)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}

	cfg, err := fetchServerConfig(r.Context(), server, req.Username, req.AuthToken, req.TenantID)
	if err != nil {
		uiLog(1, "uiapi: failed to fetch server config:", err.Error())
	}
	setSession(req.Username, req.AuthToken, req.TenantID, cfg)
	setStatus(Restoring)
	if err := restoreDesiredConnections(req.Username, req.TenantID); err != nil {
		uiLog(1, "uiapi: failed to restore previous connections:", err.Error())
	}
	setStatus(Running)
	uiLog(0, fmt.Sprintf("uiapi: session configured user=%s tenant=%s server=%s", req.Username, req.TenantID, server))
	w.WriteHeader(http.StatusOK)
}

func releaseSession(w http.ResponseWriter, r *http.Request) {
	clearToken := r.URL.Query().Get("clear_token") == "true"
	setStatus(Closing)
	// Never clear CurrServer / .serverctx on logout — Settings should keep
	// the last saved server so the user does not re-enter it.
	if err := releaseSessionFn(false); err != nil {
		uiLog(1, "uiapi: error releasing session:", err.Error())
	}
	if err := clearSession(clearToken); err != nil {
		uiLog(1, "uiapi: error clearing session:", err.Error())
	}
	setStatus(Idle)
	w.WriteHeader(http.StatusOK)
}

func listConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	if !isSessionActive() && !isRegistered(serverAddress()) {
		writeSessionRequired(w)
		return
	}
	connections, err := listConnections()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(connections)
}

func activateConnection(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !isSessionActive() && !isRegistered(serverAddress()) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	disconnect, err := prepareConnect(network)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	setStatus(Loading)
	for _, name := range disconnect {
		if err := disconnectNetwork(name); err != nil {
			setStatus(Running)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
	}
	if err := connectNetwork(network); err != nil {
		setStatus(Running)
		if isJITAccessError(err) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		if isApprovalAccessError(err) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	setStatus(Running)
	conn, err := listConnections()
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(conn[network])
}

func deactivateConnection(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	setStatus(Loading)
	if err := disconnectNetwork(network); err != nil {
		setStatus(Running)
		if err.Error() == "node is already disconnected" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	setStatus(Running)
	w.WriteHeader(http.StatusOK)
}

func isJITAccessError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "JIT access required")
}

func isApprovalAccessError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "host approval pending") ||
		strings.Contains(msg, "host approval required") ||
		strings.Contains(msg, "doesn't meet security requirements")
}

func writeSessionRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "session required"})
}

func requireSession(w http.ResponseWriter) (server, token string, ok bool) {
	if !isSessionActive() {
		uiLog(0, "uiapi: session required but inactive (JWT expired or not logged in)")
		writeSessionRequired(w)
		return "", "", false
	}
	server, _, token = sessionToken()
	if server == "" {
		server = serverAddress()
	}
	if token == "" {
		uiLog(0, "uiapi: session required but auth token missing")
		writeSessionRequired(w)
		return "", "", false
	}
	return server, token, true
}

func listNetworksHandler(w http.ResponseWriter, r *http.Request) {
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	networks, err := fetchNetworks(server, token)
	if err != nil {
		uiLog(0, "uiapi: GET /networks device API failed:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	if networks == nil {
		networks = []models.DeviceNetwork{}
	}
	uiLog(0, fmt.Sprintf("uiapi: GET /networks ok server=%s count=%d", server, len(networks)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(networks)
}

func joinNetworkHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	setStatus(Loading)
	defer setStatus(Running)
	joinStatus, err := joinNetwork(network, server, token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	if joinStatus == "pending" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func leaveNetworkHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	setStatus(Loading)
	defer setStatus(Running)
	if err := disconnectNetwork(network); err != nil && err.Error() != "node is already disconnected" {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	if err := leaveNetwork(network, server, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func cancelJoinHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	setStatus(Loading)
	defer setStatus(Running)
	if err := cancelJoin(network, server, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func requestJITHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reason == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	if err := requestJIT(network, server, token, req.Reason); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func syncHandler(w http.ResponseWriter, r *http.Request) {
	_, token, ok := requireSession(w)
	if !ok {
		return
	}
	setStatus(Loading)
	defer setStatus(Running)
	if err := syncDevice(token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeExitNodeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	msg := err.Error()
	switch {
	case strings.Contains(msg, "does not have access"),
		strings.Contains(msg, "forbidden"):
		status = http.StatusForbidden
	case strings.Contains(msg, "not joined"),
		strings.Contains(msg, "is required"),
		strings.Contains(msg, "not found"),
		strings.Contains(msg, "not an active internet"),
		strings.Contains(msg, "cannot select itself"):
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Message: msg})
}

func listExitNodesHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "network is required"})
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	nodes, err := listExitNodes(network, server, token)
	if err != nil {
		uiLog(0, "uiapi: GET /networks/"+network+"/exit_nodes failed:", err.Error())
		writeExitNodeErr(w, err)
		return
	}
	if nodes == nil {
		nodes = []models.DeviceExitNode{}
	}
	uiLog(0, fmt.Sprintf("uiapi: GET /networks/%s/exit_nodes ok count=%d", network, len(nodes)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
}

func getExitNodeHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "network is required"})
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	node, err := getSelectedExitNode(network, server, token)
	if err != nil {
		writeExitNodeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if node == nil {
		_ = json.NewEncoder(w).Encode(nil)
		return
	}
	_ = json.NewEncoder(w).Encode(node)
}

func selectExitNodeHandler(w http.ResponseWriter, r *http.Request) {
	network := r.PathValue("network")
	if network == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "network is required"})
		return
	}
	var req models.DeviceExitNodeSelectionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "invalid request body"})
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	node, err := selectExitNode(network, server, token, req.EgressID)
	if err != nil {
		writeExitNodeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if node == nil {
		_ = json.NewEncoder(w).Encode(nil)
		return
	}
	_ = json.NewEncoder(w).Encode(node)
}
