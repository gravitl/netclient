package config

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

// ClientConfig - struct for dealing with client configuration
type ClientConfig struct {
	Server          models.ServerConfig `yaml:"server"`
	Node            models.Node         `yaml:"node"`
	NetworkSettings models.Network      `yaml:"networksettings"`
	Network         string              `yaml:"network"`
	Daemon          string              `yaml:"daemon"`
	OperatingSystem string              `yaml:"operatingsystem"`
	AccessKey       string              `yaml:"accesskey"`
	PublicIPService string              `yaml:"publicipservice"`
	SsoServer       string              `yaml:"sso"`
}

// ReadConfig - reads a config of a client from disk for specified network
func ReadConfig(network string) (*ClientConfig, error) {
	if network == "" {
		err := errors.New("no network provided - exiting")
		return nil, err
	}
	home := GetNetclientPath() + "config/"
	file := fmt.Sprintf(home + "netconfig-" + network)
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
