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
	req.Server = strings.TrimSpace(req.Server)
	if req.Server == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if isServerSet(req.Server) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if isSessionActive() {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := setPendingServer(req.Server); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func getServer(w http.ResponseWriter, r *http.Request) {
	server, username, authToken := sessionToken()
	if server == "" {
		server = serverAddress()
	}
	resp := GetServerResponse{
		Status:    getStatus(),
		Server:    server,
		Username:  username,
		AuthToken: authToken,
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

	if err := registerSession(server, req.Username, req.AuthToken, req.Password); err != nil {
		setStatus(Idle)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
		return
	}

	cfg, err := fetchServerConfig(r.Context(), server, req.Username, req.AuthToken)
	if err != nil {
		slog.Warn("uiapi: failed to fetch server config", "error", err)
	} else {
		setSession(req.Username, req.AuthToken, cfg)
	}
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
