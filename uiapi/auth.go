package uiapi

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

)

const defaultAuthKey = "ZZy@PARn4$%2*I#jMVE^2X*b#$U0APqIrGSKiB$dV4"

func authKeyPath() string {
	return filepath.Join(GetDesktopConfigPath(), ".uiapi_key")
}

func loadAuthKey() string {
	data, err := os.ReadFile(authKeyPath())
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return key
		}
	}
	return defaultAuthKey
}

func ensureAuthKey() error {
	if err := ensureDesktopConfigDir(); err != nil {
		return err
	}
	path := authKeyPath()
	if _, err := os.Stat(path); err == nil {
		// Desktop app runs as the logged-in user; key must be world-readable.
		_ = os.Chmod(path, 0644)
		return nil
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	return os.WriteFile(path, []byte(key), 0644)
}
