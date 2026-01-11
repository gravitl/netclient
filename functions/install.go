package functions

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"golang.org/x/exp/slog"
)

// Install - installs binary/daemon
func Install() error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	// Normalize paths for proper comparison, especially on Windows
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	sourceAbs = filepath.Clean(sourceAbs)

	destination := config.GetNetclientInstallPath()
	// filepath.Abs works even if the file doesn't exist - it resolves the path
	destAbs, err := filepath.Abs(destination)
	if err != nil {
		// Fallback: construct absolute path from directory and filename
		destDir := filepath.Dir(destination)
		destDirAbs, err2 := filepath.Abs(destDir)
		if err2 == nil {
			destAbs = filepath.Join(destDirAbs, filepath.Base(destination))
		} else {
			// Last resort: use cleaned destination
			destAbs = filepath.Clean(destination)
		}
	}
	destAbs = filepath.Clean(destAbs)

	// On Windows, also compare case-insensitively
	if runtime.GOOS == "windows" {
		if strings.EqualFold(sourceAbs, destAbs) {
			fmt.Println("attempting to reinstall netclient on top of itself")
			fmt.Println("  specify the full path of the new binary")
			fmt.Println("  eg ./netclient install")
			return errors.New("path error")
		}
	} else {
		if sourceAbs == destAbs {
			fmt.Println("attempting to reinstall netclient on top of itself")
			fmt.Println("  specify the full path of the new binary")
			fmt.Println("  eg ./netclient install")
			return errors.New("path error")
		}
	}
	if err := daemon.Stop(); err != nil {
		slog.Warn("stopping netclient daemon", "error", err)
	}
	time.Sleep(time.Second << 1)
	if err := daemon.Install(); err != nil {
		slog.Error("daemon install error", "error", err)
		return err
	}
	config.Netclient().DaemonInstalled = true
	_ = config.WriteNetclientConfig()
	return daemon.Start()
}
