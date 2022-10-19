// Package config provides functions for reading the config.
package config

import (
	"net"

	"github.com/docker/distribution/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Verbosity int `yaml:"verbosity"`
}

type Server struct {
	Name   string
	Broker string
	API    string
}

type Node struct {
	ID           uuid.UUID
	Server       string
	Network      string
	NetworkRange net.IPNet
	Interface    string
	MacAddress   net.HardwareAddr
	Address      net.IPNet
	Address6     net.IPNet
	IsServer     bool
}

var Netclient *Config
var cached *Config

// FromFile reads a configuration file and returns it as a
// Config instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func FromFile() (*Config, error) {
	viper.SetConfigName("netclient.conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath("/etc/netclient/")
	viper.AddConfigPath("$HOME/.config/netclient/")
	viper.AddConfigPath(".")
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()
	viper.BindEnv("verbosity")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}
	cached = &config
	return cached, nil
}

// Get returns the parsed configuration. The fields of this configuration either
// contain values specified by the user or the zero value of the respective data
// type, e.g. "" for an un-configured string.
//
// Using Get over FromFile avoids the config file from being parsed each time
// the config is needed.
func Get() (*Config, error) {
	if cached != nil {
		return cached, nil
	}

	config, err := FromFile()
	if err != nil {
		return &Config{}, err
	}

	return config, nil
}

// ReadServerConfig reads a server configuration file and returns it as a
// Server instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func ReadServerConfig(name string) (*Server, error) {
	viper.SetConfigName(name + ".conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath("/etc/netclient/servers")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	var server *Server
	if err := viper.Unmarshal(server); err != nil {
		return nil, err
	}
	return server, nil
}

// ReadNodeConfig reads a node configuration file and returns it as a
// Node instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func ReadNodeConfig(name string) (*Node, error) {
	viper.SetConfigName(name + ".conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath("/etc/netclient/nodes")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	var node *Node
	if err := viper.Unmarshal(node); err != nil {
		return nil, err
	}
	return node, nil
}

func (node *Node) PrimaryAddress() net.IPNet {
	if node.Address.IP != nil {
		return node.Address
	}
	return node.Address6
}
