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
	"github.com/gravitl/netclient/daemon"
)

var binPath, filePath string

func createDirIfNotExists() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	binPath = filepath.Join(homeDir, ".netmaker", "bin")
	if err := os.MkdirAll(binPath, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func downloadVersion(version string) error {
	url := fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s", version, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		url += ".exe"
	}
	res, err := http.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			return errors.New("specified version of netclient doesn't exist")
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
func versionLessThan(v1, v2 string) bool {
	if v1 == "dev" {
		return false
	}
	if v2 == "dev" {
		return true
	}
	semVer1 := strings.TrimFunc(v1, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	semVer2 := strings.TrimFunc(v2, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	return semver.MustParse(semVer1).LT(semver.MustParse(semVer2))
}

// UseVersion switches the current netclient version to the one specified if available in the github releases page
func UseVersion(version string, rebootDaemon bool) error {
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
