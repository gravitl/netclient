package config

import (
	"embed"
	"os"

	"github.com/gravitl/netmaker/logger"
)

//go:embed windows_files/amd64/wireguard.dll
var wireguardDLL embed.FS

const (
	fileName32 = "C://Windows//System32//wireguard.dll"
	fileName64 = "C://Windows//SysWOW64//wireguard.dll"
)

func getEmbedded() ([]byte, error) {
	data, err := wireguardDLL.ReadFile("windows_files/amd64/wireguard.dll")
	if err != nil {
		return nil, err
	}

	return data, nil
}

func checkUID() {

	logger.Log(0, "checking for WireGuard driver...")

	dllData, err := getEmbedded()
	if err != nil {
		logger.FatalLog("could not reliably find WireGuard driver 0")
	}

	_, err = os.OpenFile(fileName32, os.O_RDONLY, os.ModePerm)
	if os.IsNotExist(err) {
		if err = os.WriteFile(fileName32, dllData, os.ModePerm); err != nil {
			logger.FatalLog("could not reliably write WireGuard driver, please ensure Netclient is running with Admin permissions")
		}
	} else if err != nil {
		logger.FatalLog("could not reliably find WireGuard driver 1")
	}

	_, err = os.OpenFile(fileName64, os.O_RDONLY, os.ModePerm)
	if os.IsNotExist(err) {
		if err = os.WriteFile(fileName64, dllData, os.ModePerm); err != nil {
			logger.FatalLog("could not reliably write WireGuard driver, please ensure Netclient is running with Admin permissions")
		}
	} else if err != nil {
		logger.FatalLog("could not reliably find WireGuard driver 2")
	}

	logger.Log(0, "finished checking for WireGuard driver!")
}
