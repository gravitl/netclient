package config

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gravitl/netmaker/logger"
)

// WindowsShouldCopyState reports whether a legacy install file is config
// rather than a binary. Executables, driver DLLs, and the WinSW xml stay in
// the install directory.
func WindowsShouldCopyState(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasSuffix(lower, ".exe"),
		strings.HasSuffix(lower, ".dll"),
		lower == "winsw.xml",
		strings.HasSuffix(lower, ".tmp"):
		return false
	default:
		return true
	}
}

// CopyWindowsLegacyState copies config from Program Files (x86)\Netclient into
// Program Files\Netclient. Existing destination files are left alone.
// A no-op when there is nothing to copy, including on non-Windows hosts.
func CopyWindowsLegacyState() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	legacy := strings.TrimRight(WindowsLegacyDir, `\/`)
	dest := strings.TrimRight(WindowsInstallDir, `\/`)
	if !legacyHasState(legacy) {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dest, "netclient.json")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	logger.Log(0, "copying netclient state from", legacy, "to", dest)
	return copyStateTree(legacy, dest)
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
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyStateTree(srcPath, dstPath); err != nil {
				return err
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
			return err
		}
	}
	return nil
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
