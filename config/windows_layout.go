package config

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gravitl/netmaker/logger"
)

const windowsStateMigratedMarker = ".state-migrated"

// WindowsShouldCopyState reports whether a legacy install file is config
// rather than a binary. Executables, driver DLLs, and the WinSW xml stay in
// the install directory.
func WindowsShouldCopyState(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasSuffix(lower, ".exe"),
		strings.HasSuffix(lower, ".dll"),
		lower == "winsw.xml",
		lower == windowsStateMigratedMarker,
		strings.HasSuffix(lower, ".tmp"):
		return false
	default:
		return true
	}
}

func requiredLegacyState(name string) bool {
	switch strings.ToLower(filepath.Base(name)) {
	case "netclient.json", "servers.json":
		return true
	default:
		return false
	}
}

// CopyWindowsLegacyState copies config from Program Files (x86)\Netclient into
// Program Files\Netclient. The copy is finished only after .state-migrated is
// written. A no-op when there is nothing to copy, including on non-Windows hosts.
func CopyWindowsLegacyState() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	legacy := strings.TrimRight(WindowsLegacyDir, `\/`)
	dest := strings.TrimRight(WindowsInstallDir, `\/`)
	if !legacyHasState(legacy) {
		return nil
	}
	marker := filepath.Join(dest, windowsStateMigratedMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	logger.Log(0, "copying netclient state from", legacy, "to", dest)
	if err := copyStateTree(legacy, dest); err != nil {
		return err
	}
	return os.WriteFile(marker, nil, 0600)
}

func legacyHasState(dir string) bool {
	for _, name := range []string{"netclient.json", "servers.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func copyStateTree(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	var failed error
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyStateTree(srcPath, dstPath); err != nil {
				failed = err
			}
			continue
		}
		if !WindowsShouldCopyState(entry.Name()) {
			continue
		}
		if _, err := os.Stat(dstPath); err == nil {
			continue
		}
		if err := copyStateFile(srcPath, dstPath); err != nil {
			_ = os.Remove(dstPath)
			logger.Log(0, "legacy state copy failed:", dstPath, err.Error())
			if requiredLegacyState(entry.Name()) {
				failed = err
			}
		}
	}
	return failed
}

func copyStateFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
