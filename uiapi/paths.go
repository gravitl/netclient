package uiapi

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/gravitl/netclient/config"
)

// GetConfigPath returns the netclient config directory (single source of truth for uiapi files).
// Tests may override via SetConfigPathForTest.
func GetConfigPath() string {
	if p := configPathForTest; p != "" {
		return p
	}
	return config.GetNetclientPath()
}

// configPathForTest, when non-empty, redirects session/config file I/O for tests.
var configPathForTest string

// SetConfigPathForTest redirects GetConfigPath. Pass "" to restore the default.
func SetConfigPathForTest(dir string) {
	configPathForTest = dir
}

func legacyDesktopConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join("C:\\", "Users", "Public", "netmaker-rac")
	case "darwin":
		return filepath.Join("/", "Users", "Shared", "netmaker-rac")
	default:
		return filepath.Join("/", "opt", "netmaker-rac")
	}
}

func ensureConfigDir() error {
	return os.MkdirAll(GetConfigPath(), 0775)
}

func migrateLegacyFile(dest, src string, perm os.FileMode) {
	if _, err := os.Stat(dest); err == nil {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	if err := ensureConfigDir(); err != nil {
		return
	}
	_ = os.WriteFile(dest, data, perm)
}

func migrateLegacyConfig() {
	legacy := legacyDesktopConfigPath()
	migrateLegacyFile(
		filepath.Join(GetConfigPath(), ".uisession.json"),
		filepath.Join(legacy, ".uisession.json"),
		0600,
	)
}
