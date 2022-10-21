// Package config provides functions for reading the config.
package config

import (
	"log"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LINUX_APP_DATA_PATH - linux path
const LINUX_APP_DATA_PATH = "/etc/netclient/"

// MAC_APP_DATA_PATH - mac path
const MAC_APP_DATA_PATH = "/Applications/Netclient/"

// WINDOWS_APP_DATA_PATH - windows path
const WINDOWS_APP_DATA_PATH = "C:\\Program Files (x86)\\Netclient\\"

type Config struct {
	Verbosity int `yaml:"verbosity"`
}

type Server struct {
	Name    string
	Broker  string
	API     string
	Version string
	DNSMode bool
	Is_EE   bool
}

type Node struct {
	ID                  uuid.UUID
	Name                string
	OS                  string
	Network             string
	Password            string
	NetworkRange        net.IPNet
	NetworkRange6       net.IPNet
	Interface           string
	Server              string
	Connected           bool
	MacAddress          net.HardwareAddr
	Address             net.IPNet
	Address6            net.IPNet
	ListenPort          int
	LocalListenPort     int
	MTU                 int
	PersistentKeepalive int
	PrivateKey          wgtypes.Key
	PublicKey           wgtypes.Key
	PostUp              string
	PostDown            string
	IsServer            bool
	UDPHolePunch        bool
	IsEgressGateway     bool
	IsIngressGateway    bool
	IPForwarding        bool
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
	viper.AddConfigPath(GetNetclientServerPath())
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
	viper.AddConfigPath(GetNetclientNodePath())
	if err := viper.ReadInConfig(); err != nil {
		//	if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
		log.Println("readconfig", err)
		return nil, err
		//}
	}
	var node *Node
	if err := viper.Unmarshal(node); err != nil {
		log.Println("unmarshal", err)
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

func WriteNodeConfig(node *Node) error {
	viper.SetConfigName(node.Network + ".conf")
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientNodePath())
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

func ConvertNode(s *models.Node) *Node {
	var n Node
	var err error
	n.ID, err = uuid.Parse(s.ID)
	if err != nil {
		logger.Log(0, "failed to parse ID", err.Error())
		return nil
	}
	n.Name = s.Name
	n.Network = s.Network
	n.Password = s.Password
	n.NetworkRange = toIPNet(s.NetworkSettings.AddressRange)
	n.NetworkRange6 = toIPNet(s.NetworkSettings.AddressRange6)
	n.Interface = s.Interface
	n.Server = s.Server
	n.Connected, _ = strconv.ParseBool(s.Connected)
	n.MacAddress, _ = net.ParseMAC(s.MacAddress)
	n.Address = toIPNet(s.Address)
	n.Address6 = toIPNet(s.Address6)
	n.ListenPort = int(s.ListenPort)
	n.MTU = int(s.MTU)
	n.PersistentKeepalive = int(s.PersistentKeepalive)
	n.PublicKey, _ = wgtypes.ParseKey(s.PublicKey)
	n.PostUp = s.PostUp
	n.PostDown = s.PostDown
	n.IsEgressGateway, _ = strconv.ParseBool(s.IsEgressGateway)
	n.IsIngressGateway, _ = strconv.ParseBool(s.IsIngressGateway)
	n.IPForwarding, _ = strconv.ParseBool(s.IPForwarding)
	return &n
}

func toIPNet(cidr string) net.IPNet {
	_, response, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}
	}
	return *response
}

func WriteServerConfig(cfg *models.ServerConfig) error {
	var s Server
	s.Name = strings.Replace(cfg.Server, "broker.", "", 1)
	s.Broker = cfg.Server
	s.API = cfg.API
	s.DNSMode, _ = strconv.ParseBool(cfg.DNSMode)
	s.Version = cfg.Version
	s.Is_EE = cfg.Is_EE

	viper.SetConfigName(s.Name)
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientServerPath())
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		viper.Set(v.Type().Field(i).Name, v.Field(i))
	}

	if err := viper.WriteConfig(); err != nil {
		return err
	}
	return nil
}

func SaveBackups(network string) error {
	input := GetNetclientNodePath() + network + ".conf"
	back := input + ".bak"
	if err := copyFile(input, back); err != nil {
		return err
	}
	n, err := ReadNodeConfig(network)
	if err != nil {
		return err
	}
	input = GetNetclientServerPath() + n.Server
	back = input + ".bak"
	if err := copyFile(input, back); err != nil {
		return err
	}
	return nil
}

func copyFile(input, output string) error {
	if fileExists(input) {
		file, err := os.ReadFile(input)
		if err != nil {
			logger.Log(0, "failed to read ", input, " to make a backup")
			return err
		}
		if err = os.WriteFile(output, file, 0600); err != nil {
			logger.Log(0, "failed to copy backup to ", output)
			return err
		}
	}
	return nil
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

// GetNetclientNodePath - gets path to netclient node configuration files
func GetNetclientNodePath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH + "\\nodes\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "/nodes/"
	} else {
		return LINUX_APP_DATA_PATH + "/nodes/"
	}
}

// GetNetclientServerPath - gets path to netclient server configuration files
func GetNetclientServerPath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH + "\\servers\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "/servers/"
	} else {
		return LINUX_APP_DATA_PATH + "/servers/"
	}
}

// GetNetclientInterfacePath- gets path to netclient server configuration files
func GetNetclientInterfacePath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH + "\\interfaces\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "/interfaces/"
	} else {
		return LINUX_APP_DATA_PATH + "/interfaces/"
	}
}

func fileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
