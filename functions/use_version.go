package functions

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gravitl/netclient/daemon"
)

var binPath, filePath string

func createDirIfNotExists() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	binPath = filepath.Join(homeDir, ".netmaker", "bin")
	if err := os.MkdirAll(binPath, os.ModePerm); err != nil {
		log.Fatal(err)
	}
}

func downloadVersion(version string) {
	url := fmt.Sprintf("https://github.com/gravitl/netclient/releases/download/%s/netclient-%s-%s", version, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		url += ".exe"
	}
	res, err := http.Get(url)
	if err != nil {
		log.Fatal("Error making HTTP request: ", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			log.Fatal("Specified version of netclient doesn't exist")
		}
		log.Fatal("Error making HTTP request Code: ", res.StatusCode)
	}
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	if _, err := io.Copy(file, res.Body); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(filePath, 0755); err != nil {
		log.Fatal(err)
	}
}

// UseVersion switches the current netclient version to the one specified if available in the github releases page
func UseVersion(version string) {
	createDirIfNotExists()
	filePath = filepath.Join(binPath, "netclient-"+version)
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		downloadVersion(version)
	}
	daemon.Stop()
	dst, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	src, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	tmpPath := dst + "-tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		log.Fatal(err)
	}
	defer tmpFile.Close()
	if _, err := tmpFile.Write(src); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		log.Fatal(err)
	}
	if err := os.Remove(dst); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		log.Fatal(err)
	}
	daemon.Start()
}
