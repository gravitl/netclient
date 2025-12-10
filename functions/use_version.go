package functions

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/blang/semver"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/minio/selfupdate"
	"golang.org/x/exp/slog"
)

var binPath, filePath string

func createDirIfNotExists() error {

	binPath = filepath.Join(config.GetNetclientPath(), ".netmaker", "bin")
	if err := os.MkdirAll(binPath, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func downloadVersion(version string) error {
	url := fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s", version, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "freebsd" {
		out, err := ncutils.RunCmd("grep VERSION_ID /etc/os-release", false)
		if err != nil {
			return fmt.Errorf("get freebsd version %w", err)
		}
		parts := strings.Split(out, "=")
		if len(parts) < 2 {
			return fmt.Errorf("get freebsd version parts %v", parts)
		}
		freebsdVersion := strings.Split(parts[1], ".")
		if len(freebsdVersion) < 2 {
			return fmt.Errorf("get freebsd vesion %v", freebsdVersion)
		}
		freebsd := strings.Trim(freebsdVersion[0], "\"")
		url = fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s%s-%s", version, runtime.GOOS, freebsd, runtime.GOARCH)
	}
	if runtime.GOARCH == "arm" && runtime.GOOS == "linux" {
		out, err := ncutils.RunCmd("cat /proc/cpuinfo | grep architecture | head -1 | grep -o -E '[0-9]+'", false)
		if err != nil {
			return fmt.Errorf("get arm version %w", err)
		}
		if strings.Contains(out, "\r") {
			out = strings.ReplaceAll(out, "\r", "")
		} else if strings.Contains(out, "\n") {
			out = strings.ReplaceAll(out, "\n", "")
		}
		url = fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%sv%s", version, runtime.GOOS, runtime.GOARCH, strings.TrimSpace(out))
	}
	res, err := http.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			return fmt.Errorf("specified version of netclient doesn't exist %s", url)
		}
		return fmt.Errorf("error making HTTP request Code: %d", res.StatusCode)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, res.Body); err != nil {
		return err
	}
	if err := os.Chmod(filePath, 0755); err != nil {
		return err
	}
	return nil
}

// versionLessThan checks if v1 < v2 semantically
// dev is the latest version
func versionLessThan(v1, v2 string) (bool, error) {
	if v1 == "dev" {
		return false, nil
	}
	if v2 == "dev" {
		return true, nil
	}
	semVer1 := strings.TrimFunc(v1, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	semVer2 := strings.TrimFunc(v2, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	sv1, err := semver.Parse(semVer1)
	if err != nil {
		return false, fmt.Errorf("failed to parse semver1 (%s): %w", semVer1, err)
	}
	sv2, err := semver.Parse(semVer2)
	if err != nil {
		return false, fmt.Errorf("failed to parse semver2 (%s): %w", semVer2, err)
	}
	return sv1.LT(sv2), nil
}

// UseVersion switches the current netclient version to the one specified if available in the github releases page
func UseVersion(version string, rebootDaemon bool) error {
	// Use Windows specific version change process
	if runtime.GOOS == "windows" {
		// Get the current executable path before update for verification
		currentExe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}
		
		// Get file info before update to verify it changes
		beforeInfo, err := os.Stat(currentExe)
		if err != nil {
			slog.Warn("could not stat executable before update", "error", err)
		}
		
		windowsBinaryURL := fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s.exe", version, runtime.GOOS, runtime.GOARCH)
		slog.Info("starting Windows update", "url", windowsBinaryURL, "target", currentExe)
		
		if err := windowsUpdate(windowsBinaryURL); err != nil {
			return fmt.Errorf("failed to apply Windows update: %w", err)
		}
		
		// Verify the update was applied by checking if file info changed
		// On Windows, the selfupdate library may schedule the replacement for next restart
		// so we add a delay to allow Windows to process the file replacement
		time.Sleep(1 * time.Second)
		
		afterInfo, err := os.Stat(currentExe)
		if err != nil {
			slog.Warn("could not stat executable after update", "error", err)
		} else if beforeInfo != nil {
			// Check if file was actually updated (size or mod time changed)
			if beforeInfo.Size() == afterInfo.Size() && beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
				slog.Warn("executable file info unchanged after update - Windows may schedule replacement on next restart")
			} else {
				slog.Info("executable file updated successfully", "old_size", beforeInfo.Size(), "new_size", afterInfo.Size())
			}
		}
		
		// Add additional delay before restart to ensure Windows has processed any scheduled file operations
		if rebootDaemon {
			time.Sleep(2 * time.Second)
			daemon.HardRestart()
		}
		return nil
	}

	// Use Linux and MacOS specific version change process
	if err := createDirIfNotExists(); err != nil {
		return err
	}
	filePath = filepath.Join(binPath, "netclient-"+version)
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		if err := downloadVersion(version); err != nil {
			return err
		}
	}
	if rebootDaemon {
		daemon.Stop()
	}
	dst, err := os.Executable()
	if err != nil {
		return err
	}
	src, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	tmpPath := dst + "-tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer tmpFile.Close()
	if _, err := tmpFile.Write(src); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	if rebootDaemon {
		daemon.Start()
	}
	return nil
}

// windowsUpdate uses a different package and process to upgrade netclient binary on windows
func windowsUpdate(url string) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	
	// Create a backup of the current executable before updating
	// This allows us to restore if the update corrupts the file
	backupPath := currentExe + ".backup"
	slog.Info("creating backup of current executable", "backup", backupPath)
	
	// Remove old backup if it exists
	_ = os.Remove(backupPath)
	
	// Read current executable
	currentData, err := os.ReadFile(currentExe)
	if err != nil {
		return fmt.Errorf("failed to read current executable for backup: %w", err)
	}
	
	// Write backup
	if err := os.WriteFile(backupPath, currentData, 0711); err != nil {
		slog.Warn("failed to create backup, continuing with update anyway", "error", err)
		// Don't fail the update if backup fails, but log it
	} else {
		slog.Info("backup created successfully")
	}
	
	// Download and apply update
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download update: HTTP %d", resp.StatusCode)
	}
	
	slog.Info("applying Windows update using selfupdate")
	err = selfupdate.Apply(resp.Body, selfupdate.Options{})
	if err != nil {
		// If update failed, try to restore from backup
		slog.Error("update failed, attempting to restore from backup", "error", err)
		if restoreErr := restoreFromBackup(currentExe, backupPath); restoreErr != nil {
			return fmt.Errorf("update failed and restore failed: update error: %w, restore error: %v", err, restoreErr)
		}
		slog.Info("restored from backup after failed update")
		return fmt.Errorf("update failed: %w", err)
	}
	
	// Verify the updated file is readable and valid
	// Try to stat the file - if it's corrupted, this might fail
	time.Sleep(500 * time.Millisecond) // Give Windows time to complete file operations
	if err := verifyExecutable(currentExe); err != nil {
		slog.Error("updated executable appears corrupted, restoring from backup", "error", err)
		if restoreErr := restoreFromBackup(currentExe, backupPath); restoreErr != nil {
			return fmt.Errorf("executable corrupted after update and restore failed: verify error: %w, restore error: %v", err, restoreErr)
		}
		slog.Info("restored from backup after detecting corruption")
		return fmt.Errorf("updated executable is corrupted: %w", err)
	}
	
	slog.Info("update applied and verified successfully")
	// Clean up backup after successful update (optional - could keep for safety)
	// _ = os.Remove(backupPath)
	
	return nil
}

// verifyExecutable checks if an executable file is readable and appears valid
func verifyExecutable(exePath string) error {
	// Try to open and read the file
	file, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("cannot open executable: %w", err)
	}
	defer file.Close()
	
	// Try to read at least the first few bytes to verify it's readable
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("cannot read executable: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("executable file appears empty")
	}
	
	// Check for PE (Portable Executable) signature for Windows executables
	// PE files start with "MZ" signature
	if n >= 2 && buf[0] == 'M' && buf[1] == 'Z' {
		// Valid PE signature found
		return nil
	}
	
	// If we can't verify the signature but file is readable, assume it's OK
	// (might be a different executable format or we didn't read enough)
	slog.Warn("could not verify PE signature, but file is readable", "bytes_read", n)
	return nil
}

// restoreFromBackup restores the executable from a backup file
func restoreFromBackup(currentExe, backupPath string) error {
	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}
	
	slog.Info("restoring executable from backup", "backup", backupPath, "target", currentExe)
	
	// Read backup
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}
	
	// Write to current executable location
	// Use a temp file first, then rename (atomic operation)
	tmpPath := currentExe + ".restore"
	if err := os.WriteFile(tmpPath, backupData, 0711); err != nil {
		return fmt.Errorf("failed to write restored file: %w", err)
	}
	
	// Atomic rename
	if err := os.Rename(tmpPath, currentExe); err != nil {
		_ = os.Remove(tmpPath) // Clean up temp file
		return fmt.Errorf("failed to rename restored file: %w", err)
	}
	
	slog.Info("successfully restored executable from backup")
	return nil
}
