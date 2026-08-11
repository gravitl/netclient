package config

import (
	"embed"
	"os"
	"path/filepath"

	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

//go:embed windows_files/amd64/wireguard.dll windows_files/amd64/wintun.dll
var windowsDrivers embed.FS

const (
	wireguardSys32 = `C:\Windows\System32\wireguard.dll`
	wireguardWow64 = `C:\Windows\SysWOW64\wireguard.dll`
	wintunSys32    = `C:\Windows\System32\wintun.dll`
)

func readEmbedded(name string) ([]byte, error) {
	return windowsDrivers.ReadFile(name)
}

func ensureDLL(path string, data []byte, label string) {
	_, err := os.Stat(path)
	if err == nil {
		return
	}
	if !os.IsNotExist(err) {
		logger.FatalLog("could not reliably find " + label + " at " + path + ": " + err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		logger.FatalLog("could not create directory for " + label + ": " + err.Error())
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		logger.FatalLog("could not reliably write " + label + " to " + path + ", please ensure Netclient is running with Admin permissions: " + err.Error())
	}
	slog.Info("installed Windows driver DLL", "path", path)
}

// CheckUID installs WireGuardNT and Wintun DLLs required on Windows.
// Wintun is required for userspace WireGuard (TCP uplink). The Go wintun
// package loads wintun.dll from the application directory or System32 and
// panics if it is missing.
func CheckUID() {
	logger.Log(1, "checking for WireGuard / Wintun drivers...")

	wgData, err := readEmbedded("windows_files/amd64/wireguard.dll")
	if err != nil {
		logger.FatalLog("could not read embedded WireGuard driver: " + err.Error())
	}
	ensureDLL(wireguardSys32, wgData, "WireGuard driver")
	ensureDLL(wireguardWow64, wgData, "WireGuard driver")

	wintunData, err := readEmbedded("windows_files/amd64/wintun.dll")
	if err != nil {
		logger.FatalLog("could not read embedded Wintun driver: " + err.Error())
	}
	// System32 — LoadLibraryEx searches LOAD_LIBRARY_SEARCH_SYSTEM32.
	ensureDLL(wintunSys32, wintunData, "Wintun driver")
	// Application directory — preferred search path for wintun.dll.
	if exe, err := os.Executable(); err == nil {
		ensureDLL(filepath.Join(filepath.Dir(exe), "wintun.dll"), wintunData, "Wintun driver")
	} else {
		slog.Warn("could not resolve executable path for Wintun install", "error", err)
	}

	logger.Log(1, "finished checking for WireGuard / Wintun drivers!")
}
