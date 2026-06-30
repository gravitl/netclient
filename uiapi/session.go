package uiapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	nmConfig "github.com/gravitl/netmaker/config"
)

type persistedSession struct {
	PendingServer string                `json:"pending_server"`
	Username      string                `json:"username"`
	AuthToken     string                `json:"auth_token"`
	ServerConfig  nmConfig.ServerConfig `json:"server_config"`
}

type sessionState struct {
	mu            sync.RWMutex
	status        Status
	pendingServer string
	username      string
	authToken     string
	serverConfig  nmConfig.ServerConfig
	expiresAt     time.Time
}

var session sessionState

func sessionPath() string {
	return filepath.Join(GetDesktopConfigPath(), ".uisession.json")
}

func legacySessionPath() string {
	return filepath.Join(GetDesktopConfigPath(), "ctx.json")
}

type legacyDaemonContext struct {
	Server    string `json:"server"`
	Username  string `json:"username"`
	AuthToken string `json:"auth_token"`
}

func loadSession() {
	if stored, ok := readPersistedSession(sessionPath()); ok {
		applyPersistedSession(stored)
		return
	}
	if stored, ok := loadLegacySession(); ok {
		applyPersistedSession(stored)
		_ = saveSession()
	}
}

func readPersistedSession(path string) (persistedSession, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedSession{}, false
	}
	var stored persistedSession
	if err := json.Unmarshal(data, &stored); err != nil {
		return persistedSession{}, false
	}
	return stored, true
}

func loadLegacySession() (persistedSession, bool) {
	data, err := os.ReadFile(legacySessionPath())
	if err != nil {
		return persistedSession{}, false
	}
	var legacy legacyDaemonContext
	if err := json.Unmarshal(data, &legacy); err != nil {
		return persistedSession{}, false
	}
	if legacy.Server == "" && legacy.Username == "" && legacy.AuthToken == "" {
		return persistedSession{}, false
	}
	return persistedSession{
		PendingServer: legacy.Server,
		Username:      legacy.Username,
		AuthToken:     legacy.AuthToken,
	}, true
}

func applyPersistedSession(stored persistedSession) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.pendingServer = stored.PendingServer
	session.username = stored.Username
	session.authToken = stored.AuthToken
	session.serverConfig = stored.ServerConfig
	if session.authToken != "" {
		session.status = Running
		if exp, expired := tokenExpiry(session.authToken); !expired {
			session.expiresAt = exp
		}
	}
}

func saveSession() error {
	session.mu.RLock()
	stored := persistedSession{
		PendingServer: session.pendingServer,
		Username:      session.username,
		AuthToken:     session.authToken,
		ServerConfig:  session.serverConfig,
	}
	session.mu.RUnlock()
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := ensureDesktopConfigDir(); err != nil {
		return err
	}
	return os.WriteFile(sessionPath(), data, 0600)
}

func clearSession(clearToken bool) error {
	session.mu.Lock()
	session.status = Idle
	session.username = ""
	session.authToken = ""
	session.serverConfig = nmConfig.ServerConfig{}
	session.expiresAt = time.Time{}
	if clearToken {
		session.pendingServer = ""
	}
	session.mu.Unlock()
	if clearToken {
		return os.Remove(sessionPath())
	}
	return saveSession()
}

func isSessionActive() bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.username == "" || session.authToken == "" {
		return false
	}
	if !session.expiresAt.IsZero() && session.expiresAt.Before(time.Now()) {
		return false
	}
	return true
}

func getStatus() Status {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.status
}

func setStatus(status Status) {
	session.mu.Lock()
	session.status = status
	session.mu.Unlock()
}

func tokenExpiry(tokenString string) (time.Time, bool) {
	parser := jwt.Parser{}
	claims := &jwt.RegisteredClaims{}
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil || claims.ExpiresAt == nil {
		return time.Time{}, true
	}
	return claims.ExpiresAt.Time, false
}

func setSession(username, authToken string, serverConfig nmConfig.ServerConfig) {
	exp, _ := tokenExpiry(authToken)
	session.mu.Lock()
	session.username = username
	session.authToken = authToken
	session.serverConfig = serverConfig
	session.expiresAt = exp
	session.status = Running
	session.mu.Unlock()
	_ = saveSession()
}

func sessionToken() (server, username, authToken string) {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.pendingServer, session.username, session.authToken
}

// SessionCredentials returns the active server and user token for device API calls.
func SessionCredentials() (server, authToken string) {
	session.mu.RLock()
	defer session.mu.RUnlock()
	server = session.pendingServer
	if server == "" {
		server = getCurrServerName()
	}
	return server, session.authToken
}

func configuredServer() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.pendingServer
}

func setPendingServer(server string) error {
	session.mu.Lock()
	session.pendingServer = server
	session.mu.Unlock()
	return saveSession()
}

func isServerSet(server string) bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.pendingServer == "" {
		return false
	}
	if server == "" {
		return true
	}
	return session.pendingServer == server
}

func serverConfig() nmConfig.ServerConfig {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.serverConfig
}

func racRestrictToSingleNetwork() bool {
	return serverConfig().RacRestrictToSingleNetwork
}
