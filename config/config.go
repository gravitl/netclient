// Package config provides functions for reading the config.
package config

import (
	"net"
	"reflect"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	ID               uuid.UUID
	Name             string
	Network          string
	NetworkRange     net.IPNet
	NetworkRange6    net.IPNet
	Interface        string
	Server           string
	Connected        bool
	MacAddress       net.HardwareAddr
	Address          net.IPNet
	Address6         net.IPNet
	ListenPort       int
	MTU              int
	PrivateKey       wgtypes.Key
	PostUp           string
	PostDown         string
	IsServer         bool
	UDPHolePunch     bool
	IsEgressGateway  bool
	IsIngressGateway bool
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

func WriteNodeConfig(name string, node *Node) error {
	viper.SetConfigName(name + ".conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath("/etc/netclient/nodes")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	v := reflect.ValueOf(node)
	for i := 0; i < v.NumField(); i++ {
		viper.Set(v.Type().Field(i).Name, v.Field(i))
	}

	if err := viper.WriteConfig(); err != nil {
		return err
	}
	return nil
}
