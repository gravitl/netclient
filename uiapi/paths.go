package uiapi

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetDesktopConfigPath returns the config directory used by the legacy desktop daemon.
func GetDesktopConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join("C:\\", "Users", "Public", "netmaker-rac")
	case "darwin":
		return filepath.Join("/", "Users", "Shared", "netmaker-rac")
	default:
		return filepath.Join("/", "opt", "netmaker-rac")
	}
}

func ensureDesktopConfigDir() error {
	return os.MkdirAll(GetDesktopConfigPath(), 0777)
}
