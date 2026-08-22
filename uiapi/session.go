package uiapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gravitl/netclient/config"
	nmConfig "github.com/gravitl/netmaker/config"
)

type persistedUserSession struct {
	// PendingServer is read only for one-time migration from older session files.
	PendingServer string                `json:"pending_server,omitempty"`
	Username      string                `json:"username"`
	AuthToken     string                `json:"auth_token"`
	TenantID      string                `json:"tenant_id"`
	ServerConfig  nmConfig.ServerConfig `json:"server_config"`
}

type sessionState struct {
	mu           sync.RWMutex
	status       Status
	username     string
	authToken    string
	tenantID     string
	serverConfig nmConfig.ServerConfig
	expiresAt    time.Time
}

var session sessionState

func userSessionPath() string {
	return filepath.Join(GetConfigPath(), ".uisession.json")
}

func legacySessionPath() string {
	return filepath.Join(legacyDesktopConfigPath(), "ctx.json")
}

type legacyDaemonContext struct {
	Server    string `json:"server"`
	Username  string `json:"username"`
	AuthToken string `json:"auth_token"`
}

func loadSession() {
	migrateLegacyConfig()
	config.SetServerCtx()

	if stored, ok := readPersistedUserSession(userSessionPath()); ok {
		migrateLegacyServer(stored.PendingServer)
		applyPersistedUserSession(stored)
		rewriteUserSessionIfLegacy(stored)
		return
	}
	if stored, ok := loadLegacyUserSession(); ok {
		migrateLegacyServer(stored.PendingServer)
		applyPersistedUserSession(stored)
		_ = saveUserSession()
		return
	}
}

func readPersistedUserSession(path string) (persistedUserSession, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedUserSession{}, false
	}
	var stored persistedUserSession
	if err := json.Unmarshal(data, &stored); err != nil {
		return persistedUserSession{}, false
	}
	if stored.Username == "" && stored.AuthToken == "" && stored.PendingServer == "" {
		return persistedUserSession{}, false
	}
	return stored, true
}

func loadLegacyUserSession() (persistedUserSession, bool) {
	data, err := os.ReadFile(legacySessionPath())
	if err != nil {
		return persistedUserSession{}, false
	}
	var legacy legacyDaemonContext
	if err := json.Unmarshal(data, &legacy); err != nil {
		return persistedUserSession{}, false
	}
	if legacy.Server == "" && legacy.Username == "" && legacy.AuthToken == "" {
		return persistedUserSession{}, false
	}
	return persistedUserSession{
		PendingServer: legacy.Server,
		Username:      legacy.Username,
		AuthToken:     legacy.AuthToken,
	}, true
}

func migrateLegacyServer(server string) {
	server = normalizeServerHost(server)
	if server == "" || getCurrServerName() != "" {
		return
	}
	if key := config.ResolveServerKey(server); key != "" {
		server = key
	}
	config.CurrServer = server
	_ = config.SetCurrServerCtxInFile(server)
}

func rewriteUserSessionIfLegacy(stored persistedUserSession) {
	if stored.PendingServer == "" {
		return
	}
	_ = saveUserSession()
}

func applyPersistedUserSession(stored persistedUserSession) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.username = stored.Username
	session.authToken = stored.AuthToken
	session.tenantID = stored.TenantID
	session.serverConfig = stored.ServerConfig
	if session.authToken != "" {
		exp, expired := tokenExpiry(session.authToken)
		if !expired {
			session.expiresAt = exp
			session.status = Running
		} else if !exp.IsZero() {
			session.expiresAt = exp
			session.status = Idle
		}
	}
}

func saveUserSession() error {
	session.mu.RLock()
	stored := persistedUserSession{
		Username:     session.username,
		AuthToken:    session.authToken,
		TenantID:     session.tenantID,
		ServerConfig: session.serverConfig,
	}
	session.mu.RUnlock()
	if stored.Username == "" && stored.AuthToken == "" {
		return os.Remove(userSessionPath())
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := ensureConfigDir(); err != nil {
		return err
	}
	return os.WriteFile(userSessionPath(), data, 0600)
}

func clearSession(clearServer bool) error {
	session.mu.Lock()
	session.status = Idle
	session.username = ""
	session.authToken = ""
	session.tenantID = ""
	session.serverConfig = nmConfig.ServerConfig{}
	session.expiresAt = time.Time{}
	session.mu.Unlock()
	if clearServer {
		return os.Remove(userSessionPath())
	}
	return saveUserSession()
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

func setSession(username, authToken, tenantID string, serverConfig nmConfig.ServerConfig) {
	exp, _ := tokenExpiry(authToken)
	session.mu.Lock()
	session.username = username
	session.authToken = authToken
	session.tenantID = strings.TrimSpace(tenantID)
	session.serverConfig = serverConfig
	session.expiresAt = exp
	session.status = Running
	session.mu.Unlock()
	_ = saveUserSession()
}

func sessionToken() (server, username, authToken string) {
	session.mu.RLock()
	username = session.username
	authToken = session.authToken
	session.mu.RUnlock()
	return activeServerAddress(), username, authToken
}

func sessionTenantID() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.tenantID
}

// SessionCredentials returns the active server and user token for device API calls.
func SessionCredentials() (server, authToken string) {
	session.mu.RLock()
	authToken = session.authToken
	session.mu.RUnlock()
	return activeServerAddress(), authToken
}

func configuredServer() string {
	return activeServerAddress()
}

func isServerSet(server string) bool {
	active := activeServerAddress()
	if active == "" {
		return false
	}
	if server == "" {
		return true
	}
	return normalizeServerHost(server) == active
}

func serverConfig() nmConfig.ServerConfig {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.serverConfig
}

func racRestrictToSingleNetwork() bool {
	return serverConfig().RacRestrictToSingleNetwork
}

func normalizeServerHost(server string) string {
	return strings.TrimPrefix(strings.TrimSpace(server), "https://")
}
