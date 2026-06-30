package uiapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
)

const listenAddr = "127.0.0.1:61820"

var (
	serverMu  sync.Mutex
	httpSrv   *http.Server
	listenDone chan struct{}
)

// Start launches the localhost REST API for desktop UI clients.
// Any previous instance is stopped first. The server also stops when ctx is cancelled.
func Start(ctx context.Context) {
	serverMu.Lock()
	defer serverMu.Unlock()

	stopLocked()

	if err := ensureAuthKey(); err != nil {
		slog.Warn("uiapi: failed to ensure auth key", "error", err)
	}
	loadSession()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", checkHealth)
	mux.Handle("POST /server", authMiddleware(http.HandlerFunc(configureServer)))
	mux.Handle("GET /server", authMiddleware(http.HandlerFunc(getServer)))
	mux.Handle("PUT /session", authMiddleware(http.HandlerFunc(configureSession)))
	mux.Handle("DELETE /session", authMiddleware(http.HandlerFunc(releaseSession)))
	mux.Handle("GET /connections", authMiddleware(http.HandlerFunc(listConnectionsHandler)))
	mux.Handle("GET /networks", authMiddleware(http.HandlerFunc(listNetworksHandler)))
	mux.Handle("POST /networks/{network}/join", authMiddleware(http.HandlerFunc(joinNetworkHandler)))
	mux.Handle("DELETE /networks/{network}/leave", authMiddleware(http.HandlerFunc(leaveNetworkHandler)))
	mux.Handle("DELETE /networks/{network}/cancel", authMiddleware(http.HandlerFunc(cancelJoinHandler)))
	mux.Handle("POST /networks/{network}/jit/request", authMiddleware(http.HandlerFunc(requestJITHandler)))
	mux.Handle("POST /sync", authMiddleware(http.HandlerFunc(syncHandler)))
	mux.Handle("POST /connections/{network}", authMiddleware(http.HandlerFunc(activateConnection)))
	mux.Handle("DELETE /connections/{network}", authMiddleware(http.HandlerFunc(deactivateConnection)))

	httpSrv = &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	listenDone = done

	go func() {
		defer close(done)
		slog.Info("uiapi: starting desktop API", "addr", listenAddr, "version", config.Version)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("uiapi: server error", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = Stop()
	}()
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
		slog.Warn("uiapi: shutdown error", "error", err)
	}
	return err
}

func authMiddleware(next http.Handler) http.Handler {
	key := loadAuthKey()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-netmaker-auth-key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthKey returns the local API auth key for desktop clients.
func AuthKey() string {
	return loadAuthKey()
}
