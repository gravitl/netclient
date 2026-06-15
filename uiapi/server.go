package uiapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gravitl/netclient/config"
)

const listenAddr = "127.0.0.1:61821"

// Start launches the localhost REST API for desktop UI clients.
func Start(ctx context.Context) {
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
	mux.Handle("POST /connections/{network}", authMiddleware(http.HandlerFunc(activateConnection)))
	mux.Handle("DELETE /connections/{network}", authMiddleware(http.HandlerFunc(deactivateConnection)))

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("uiapi: starting desktop API", "addr", listenAddr, "version", config.Version)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("uiapi: server error", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Warn("uiapi: shutdown error", "error", err)
		}
	}()
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
