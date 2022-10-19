// Package config provides functions for reading the config.
package config

import (
	"os"

	"github.com/kr/pretty"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Verbosity int `yaml:"verbosity"`
}

var Netclient *Config
var cached *Config

// FromFile reads a configuration file called conf.yml and returns it as a
// Config instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the following directories:
//
//   - /etc/golfballs
//   - $HOME/.golfballs
//   - .
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func FromFile() (*Config, error) {
	viper.SetConfigName("netclient.conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath("/etc/netclient/")
	viper.AddConfigPath("$HOME/.config/netclient/")
	viper.AddConfigPath(".")
	pretty.Println(1, viper.AllKeys())

	//viper.BindPFlags(flags)
	viper.BindPFlags(pflag.CommandLine)
	pretty.Println(2, viper.AllSettings())
	viper.AutomaticEnv()
	pretty.Println(3, viper.AllKeys(), "env:", os.Getenv("verbosity"))
	viper.BindEnv("verbosity")
	pretty.Println(4, viper.AllKeys(), "env:", os.Getenv("verbosity"))

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
