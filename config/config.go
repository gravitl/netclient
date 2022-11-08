// Package config provides functions for reading the config.
package config

import (
	"os"
	"runtime"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// LINUX_APP_DATA_PATH - linux path
const LINUX_APP_DATA_PATH = "/etc/netclient/"

// MAC_APP_DATA_PATH - mac path
const MAC_APP_DATA_PATH = "/Applications/Netclient/"

// WINDOWS_APP_DATA_PATH - windows path
const WINDOWS_APP_DATA_PATH = "C:\\Program Files (x86)\\Netclient\\"

var Netclient Config

type Config struct {
	Verbosity       int `yaml:"verbosity"`
	FirewallInUse   string
	Version         string
	IPForwarding    bool
	DaemonInstalled bool
	HostID          string
	HostPass        string
	OS              string
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)

}

// ReadNetclientConfig reads a configuration file and returns it as an
// instance. If no configuration file is found, nil and no error will be
// returned. The configuration mustID live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func ReadNetclientConfig() (*Config, error) {
	viper.SetConfigName("netclient.yml")
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientPath())
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	var netclient Config
	if err := viper.Unmarshal(&netclient); err != nil {
		return nil, err
	}
	return &netclient, nil
}

func WriteNetclientConfig() error {
	file := GetNetclientPath() + "netclient.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(GetNetclientPath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(Netclient)
	if err != nil {
		return err
	}
	return f.Sync()
}

// GetNetclientPath - gets netclient path locally
func GetNetclientPath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH
	} else {
		return LINUX_APP_DATA_PATH
	}
}

// GetNetclientInterfacePath- gets path to netclient server configuration files
func GetNetclientInterfacePath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH + "interfaces\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "interfaces/"
	} else {
		return LINUX_APP_DATA_PATH + "interfaces/"
	}
}

// FileExists - checks if a file exists on disk
func FileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
