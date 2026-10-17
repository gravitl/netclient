//go:build windows

package daemon

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

// MigrateWindowsService copies the running binary into Program Files and
// points the existing service at the new WinSW wrapper. True means a restart
// of the service was scheduled and the caller should exit.
func MigrateWindowsService() bool {
	if err := config.CopyWindowsLegacyState(); err != nil {
		logger.Log(0, "failed to copy legacy windows config:", err.Error())
	}
	exe, err := os.Executable()
	if err != nil {
		logger.Log(0, "windows layout: cannot locate executable:", err.Error())
		return false
	}
	legacy := strings.TrimRight(config.WindowsLegacyDir, `\/`)
	if !pathUnder(exe, legacy) && !servicePointsAtLegacy() {
		return false
	}
	installDir := strings.TrimRight(config.GetNetclientInstallDir(), `\/`)
	if pathUnder(exe, installDir) && !servicePointsAtLegacy() {
		return false
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		logger.Log(0, "windows layout: cannot create install dir:", err.Error())
		return false
	}
	if err := copyBinary(exe, filepath.Join(installDir, "netclient.exe")); err != nil {
		logger.Log(0, "windows layout: cannot copy netclient.exe:", err.Error())
		return false
	}
	if err := copyOptional(filepath.Join(legacy, "winsw.exe"), filepath.Join(installDir, "winsw.exe")); err != nil {
		logger.Log(0, "windows layout: cannot copy winsw.exe:", err.Error())
		return false
	}
	if !ncutils.FileExists(filepath.Join(installDir, "winsw.exe")) {
		if err := ncutils.GetEmbedded(); err != nil {
			logger.Log(0, "windows layout: cannot write winsw.exe:", err.Error())
			return false
		}
	}
	_ = copyOptional(filepath.Join(legacy, "wintun.dll"), filepath.Join(installDir, "wintun.dll"))
	if err := writeServiceConfig(); err != nil {
		logger.Log(0, "windows layout: cannot write winsw.xml:", err.Error())
		return false
	}
	winsw := filepath.Join(installDir, "winsw.exe")
	if err := exec.Command("sc.exe", "config", "netclient", "binPath=\""+winsw+"\"").Run(); err != nil {
		logger.Log(0, "windows layout: cannot retarget service:", err.Error())
		return false
	}
	logger.Log(0, "windows layout: restarting service into", installDir)
	cmd := exec.Command("cmd.exe", "/C", "sc stop netclient & sc start netclient")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008}
	if err := cmd.Start(); err != nil {
		logger.Log(0, "windows layout: cannot restart service:", err.Error())
		return false
	}
	return true
}

func servicePointsAtLegacy() bool {
	out, err := exec.Command("sc.exe", "qc", "netclient").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(`program files (x86)\netclient`))
}

func pathUnder(path, dir string) bool {
	path = strings.ToLower(filepath.Clean(path))
	dir = strings.ToLower(filepath.Clean(dir))
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}

func copyOptional(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	return copyBinary(src, dst)
}

func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
