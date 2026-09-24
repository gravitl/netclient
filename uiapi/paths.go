package uiapi

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/gravitl/netclient/config"
)

// GetConfigPath returns the netclient config directory (single source of truth for uiapi files).
func GetConfigPath() string {
	return config.GetNetclientPath()
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
