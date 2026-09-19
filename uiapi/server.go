package uiapi

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
)

const listenAddr = "127.0.0.1:61820"

var (
	serverMu   sync.Mutex
	httpSrv    *http.Server
	listenDone chan struct{}
)

// Start launches the localhost REST API for desktop UI clients.
// The listener stays up until Stop is called; repeated Start calls are no-ops
// while the server is already running.
func Start(ctx context.Context) {
	serverMu.Lock()
	defer serverMu.Unlock()

	loadSession()

	if httpSrv != nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", checkHealth)
	mux.HandleFunc("POST /server", configureServer)
	mux.HandleFunc("GET /server", getServer)
	mux.HandleFunc("GET /session", getSession)
	mux.HandleFunc("PUT /session", configureSession)
	mux.HandleFunc("DELETE /session", releaseSession)
	mux.HandleFunc("GET /connections", listConnectionsHandler)
	mux.HandleFunc("GET /networks", listNetworksHandler)
	mux.HandleFunc("POST /networks/{network}/join", joinNetworkHandler)
	mux.HandleFunc("DELETE /networks/{network}/leave", leaveNetworkHandler)
	mux.HandleFunc("DELETE /networks/{network}/cancel", cancelJoinHandler)
	mux.HandleFunc("POST /networks/{network}/jit/request", requestJITHandler)
	mux.HandleFunc("GET /networks/{network}/exit_nodes", listExitNodesHandler)
	mux.HandleFunc("GET /networks/{network}/exit_node", getExitNodeHandler)
	mux.HandleFunc("PUT /networks/{network}/exit_node", selectExitNodeHandler)
	mux.HandleFunc("POST /sync", syncHandler)
	mux.HandleFunc("POST /connections/{network}", activateConnection)
	mux.HandleFunc("DELETE /connections/{network}", deactivateConnection)

	httpSrv = &http.Server{
		Addr:              listenAddr,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	listenDone = done

	go func() {
		defer close(done)
		uiLog(0, fmt.Sprintf("uiapi: starting desktop API on %s (version %s)", listenAddr, config.Version))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			uiLog(0, "uiapi: server error:", err.Error())
		}
	}()

	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = Stop()
		}()
	}
}

// Refresh reloads persisted session state without restarting the listener.
func Refresh() {
	serverMu.Lock()
	defer serverMu.Unlock()
	if httpSrv == nil {
		return
	}
	loadSession()
}

// Stop shuts down the uiapi server and waits for the listener to exit.
func Stop() error {
	serverMu.Lock()
	defer serverMu.Unlock()
	return stopLocked()
}

func stopLocked() error {
	if httpSrv == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := httpSrv.Shutdown(shutdownCtx)
	if listenDone != nil {
		<-listenDone
		listenDone = nil
	}
	httpSrv = nil
	if err != nil {
		uiLog(0, "uiapi: shutdown error:", err.Error())
	}
	return err
}
