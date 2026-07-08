package uiapi

import (
	"encoding/json"
	"log/slog"
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	server := normalizeServerHost(req.Server)
	if server == "" {
		w.WriteHeader(http.StatusBadRequest)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	config.CurrServer = server
	if err := config.SetCurrServerCtxInFile(server); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func getServer(w http.ResponseWriter, r *http.Request) {
	server, username, authToken := sessionToken()
	resp := GetServerResponse{
		Status:     getStatus(),
		Server:     server,
		Username:   username,
		AuthToken:  authToken,
		Registered: isRegistered(server),
	}
	if isSessionActive() {
		resp.ServerConfig = serverConfig()
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("uiapi: failed to encode server response", "error", err)
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
	if prevUser != "" && prevUser != req.Username {
		if err := releaseSessionFn(false); err != nil {
			slog.Warn("uiapi: failed to disconnect prior user before session handoff", "error", err)
		}
	}

	if err := registerSession(server, req.Username, req.AuthToken, req.Password); err != nil {
		setStatus(Idle)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}

	cfg, err := fetchServerConfig(r.Context(), server, req.Username, req.AuthToken)
	if err != nil {
		slog.Warn("uiapi: failed to fetch server config", "error", err)
	}
	setSession(req.Username, req.AuthToken, cfg)
	setStatus(Running)
	w.WriteHeader(http.StatusOK)
}

func releaseSession(w http.ResponseWriter, r *http.Request) {
	clearToken := r.URL.Query().Get("clear_token") == "true"
	setStatus(Closing)
	if err := releaseSessionFn(clearToken); err != nil {
		slog.Warn("uiapi: error releasing session", "error", err)
	}
	if err := clearSession(clearToken); err != nil {
		slog.Warn("uiapi: error clearing session", "error", err)
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
		w.WriteHeader(http.StatusUnauthorized)
		return "", "", false
	}
	server, _, token = sessionToken()
	if server == "" {
		server = serverAddress()
	}
	if token == "" {
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
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}
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
		writeExitNodeErr(w, err)
		return
	}
	if nodes == nil {
		nodes = []DeviceExitNodeView{}
	}
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
	var req SelectExitNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: "invalid request body"})
		return
	}
	server, token, ok := requireSession(w)
	if !ok {
		return
	}
	setStatus(Loading)
	defer setStatus(Running)
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
