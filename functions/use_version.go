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
	"unicode"

	"github.com/blang/semver"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/minio/selfupdate"
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
		windowsBinaryURL := fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s.exe", version, runtime.GOOS, runtime.GOARCH)
		if err := windowsUpdate(windowsBinaryURL); err != nil {
			return err
		}
		if rebootDaemon {
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
	if err := os.Remove(dst); err != nil {
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
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = selfupdate.Apply(resp.Body, selfupdate.Options{})
	if err != nil {
		return err
	}
	return nil
}
