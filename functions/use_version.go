package functions

import (
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

func getUrl(version string) (url string) {
	switch runtime.GOOS {
	case "windows":
		url = fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s.exe", version, runtime.GOOS, runtime.GOARCH)
	default:
		url = fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s", version, runtime.GOOS, runtime.GOARCH)
	}
	return
}

// UseVersion switches the current netclient version to the one specified if available in the github releases page
func UseVersion(version string, rebootDaemon bool) error {

	if rebootDaemon {
		daemon.Stop()
	}
	defer func() {
		if rebootDaemon {
			daemon.Start()
		}
	}()
	if err := updateBinary(getUrl(version)); err != nil {
		return err
	}

	return nil
}

// updateBinary - func to upgrade netclient binary
func updateBinary(url string) error {
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
