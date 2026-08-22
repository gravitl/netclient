package uiapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/gravitl/netclient/config"
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
	server := normalizeServerHost(req.Server)
	if server == "" {
		if isSessionActive() {
			respondConfigureServerError(w, "cannot clear server while session is active")
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
	if key := config.ResolveServerKey(server); key != "" {
		server = key
	}
	if isServerSet(server) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if isSessionActive() {
		respondConfigureServerError(w, "cannot change server while session is active; log out first")
		return
	}
	config.CurrServer = server
	if err := config.SetCurrServerCtxInFile(server); err != nil {
		uiLog(0, "uiapi: failed to persist server context:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
	uiLog(0, fmt.Sprintf("uiapi: server set to %s", server))
	w.WriteHeader(http.StatusOK)
}

func respondConfigureServerError(w http.ResponseWriter, message string) {
	uiLog(0, "uiapi: POST /server rejected:", message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func getServer(w http.ResponseWriter, r *http.Request) {
	server, username, authToken := sessionToken()
	resp := GetServerResponse{
		Status:     getStatus(),
		Server:     server,
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
		uiLog(0, "uiapi: failed to encode server response:", err.Error())
	}
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
	setStatus(Running)
	uiLog(0, fmt.Sprintf("uiapi: session configured user=%s tenant=%s server=%s", req.Username, req.TenantID, server))
	w.WriteHeader(http.StatusOK)
}

func releaseSession(w http.ResponseWriter, r *http.Request) {
	clearToken := r.URL.Query().Get("clear_token") == "true"
	setStatus(Closing)
	if err := releaseSessionFn(clearToken); err != nil {
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
		w.WriteHeader(http.StatusBadRequest)
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

func requireSession(w http.ResponseWriter) (server, token string, ok bool) {
	if !isSessionActive() {
		uiLog(0, "uiapi: session required but inactive (JWT expired or not logged in)")
		w.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}
	server, _, token = sessionToken()
	if server == "" {
		server = serverAddress()
	}
	if token == "" {
		uiLog(0, "uiapi: session required but auth token missing")
		w.WriteHeader(http.StatusUnauthorized)
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
