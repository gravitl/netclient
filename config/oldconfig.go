package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

// ClientConfig - struct for dealing with client configuration
type ClientConfig struct {
	Server          OldNetmakerServerConfig `yaml:"server"`
	Node            models.LegacyNode       `yaml:"node"`
	NetworkSettings models.Network          `yaml:"networksettings"`
	Network         string                  `yaml:"network"`
	Daemon          string                  `yaml:"daemon"`
	OperatingSystem string                  `yaml:"operatingsystem"`
	AccessKey       string                  `yaml:"accesskey"`
	PublicIPService string                  `yaml:"publicipservice"`
	SsoServer       string                  `yaml:"sso"`
}

// ReadConfig - reads a config of a older version of client from disk for specified network
func ReadConfig(network string) (*ClientConfig, error) {
	if network == "" {
		err := errors.New("no network provided - exiting")
		return nil, err
	}
	home := GetNetclientPath() + "config/"
	if ncutils.IsWindows() {
		// for some reason windows does not use the config dir although it exists
		home = GetNetclientPath()
	}
	file := fmt.Sprint(home + "netconfig-" + network)
	log.Println("processing ", file)
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg ClientConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, err
}

// GetSystemNetworks - get networks for older version (pre v0.18.0) of netclient
func GetSystemNetworks() ([]string, error) {
	var networks []string
	confPath := GetNetclientPath() + "config/netconfig-*"
	if ncutils.IsWindows() {
		// for some reason windows does not use the config dir although it exists
		confPath = GetNetclientPath() + "netconfig-*"
	}
	files, err := filepath.Glob(confPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		// don't want files such as *.bak, *.swp
		if filepath.Ext(file) != "" {
			continue
		}
		file := filepath.Base(file)
		temp := strings.Split(file, "-")
		networks = append(networks, strings.Join(temp[1:], "-"))
	}
	return networks, nil
}
