// Package config provides functions for reading the config.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// LINUX_APP_DATA_PATH - linux path
const LINUX_APP_DATA_PATH = "/etc/netclient/"

// MAC_APP_DATA_PATH - mac path
const MAC_APP_DATA_PATH = "/Applications/Netclient/"

// WINDOWS_APP_DATA_PATH - windows path
const WINDOWS_APP_DATA_PATH = "C:\\Program Files (x86)\\Netclient\\"

var Servers map[string]Server
var Nodes map[string]Node
var Netclient Config

type Config struct {
	Verbosity       int `yaml:"verbosity"`
	FirewallInUse   string
	Version         string
	IPForwarding    bool
	DaemonInstalled bool
	HostID          string
	HostPass        string
}

type Server struct {
	Name        string
	Version     string
	API         string
	CoreDNSAddr string
	Broker      string
	MQPort      string
	MQID        string
	Password    string
	DNSMode     bool
	Is_EE       bool
	Nodes       []string
}

type Node struct {
	ID                  string
	Name                string
	OS                  string
	Network             string
	Password            string
	AccessKey           string
	NetworkRange        net.IPNet
	NetworkRange6       net.IPNet
	InternetGateway     *net.UDPAddr
	Interface           string
	Server              string
	Connected           bool
	TrafficKeys         models.TrafficKeys
	TrafficPrivateKey   *[32]byte
	MacAddress          net.HardwareAddr
	Port                int
	Endpoint            net.IPNet
	Address             net.IPNet
	Address6            net.IPNet
	ListenPort          int
	LocalAddress        net.IPNet
	LocalRange          net.IPNet
	LocalListenPort     int
	MTU                 int
	PersistentKeepalive int
	PrivateKey          wgtypes.Key
	PublicKey           wgtypes.Key
	PostUp              string
	PostDown            string
	Action              string
	IsServer            bool
	UDPHolePunch        bool
	IsLocal             bool
	IsEgressGateway     bool
	IsIngressGateway    bool
	IsStatic            bool
	IsPending           bool
	DNSOn               bool
	IsHub               bool
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)
}

// ReadNetclientConfig reads a configuration file and returns it as an
// instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
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

// ReadServerConfig reads a server configuration file and returns it as a
// Server instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func GetServers() error {
	file := GetNetclientPath() + "servers.yml"
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&Servers); err != nil {
		return err
	}
	return nil
}

func GetNodes() error {
	file := GetNetclientPath() + "nodes.yml"
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&Nodes); err != nil {
		return err
	}
	return nil
}

// ReadNodeConfig reads a node configuration file and returns it as a
// Node instance. If no configuration file is found, nil and no error will be
// returned. The configuration must live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func ReadNodeConfig() error {
	viper.SetConfigName("nodes.yml")
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientNodePath())
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Println("readconfig", err)
			return err
		}
	}
	if err := viper.Unmarshal(&Nodes); err != nil {
		log.Println("unmarshal", err)
		return err
	}
	return nil
}

func (node *Node) PrimaryAddress() net.IPNet {
	if node.Address.IP != nil {
		return node.Address
	}
	return node.Address6
}

// ReadConfig - reads a config of a client from disk for specified network
func ReadConfig(network string) (*Node, error) {
	if network == "" {
		err := errors.New("no network provided - exiting")
		return nil, err
	}
	file := GetNetclientNodePath() + network + ".yml"
	f, err := os.Open(file)
	if err != nil {
		if err = ReplaceWithBackup(network); err != nil {
			return nil, err
		}
		f, err = os.Open(file)
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()
	node := Node{}
	err = yaml.NewDecoder(f).Decode(&node)
	if err != nil {
		if err = ReplaceWithBackup(network); err != nil {
			return nil, err
		}
		f.Close()
		f, err = os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := yaml.NewDecoder(f).Decode(&node); err != nil {
			return nil, err
		}
	}
	return &node, err
}

func WriteNodeConfig() error {
	file := GetNetclientPath() + "nodes.yml"
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
	err = yaml.NewEncoder(f).Encode(Nodes)
	if err != nil {
		return err
	}
	return f.Sync()
}

func WriteServerConfig() error {
	file := GetNetclientPath() + "servers.yml"
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
	err = yaml.NewEncoder(f).Encode(Servers)
	if err != nil {
		return err
	}
	return f.Sync()
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

func OldWriteServerConfig(node Node) error {
	if node.Network == "" {
		return errors.New("no network provided --- exiting")
	}
	file := GetNetclientPath() + "servers.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(GetNetclientNodePath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(Servers)
	if err != nil {
		return err
	}
	return f.Sync()
}

func (c *Config) Save() error {
	viper.SetConfigName("netclient.yml")
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientPath())
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	v := reflect.ValueOf(c)
	for i := 0; i < v.NumField(); i++ {
		viper.Set(v.Type().Field(i).Name, v.Field(i))
	}

	return viper.WriteConfigAs(GetNetclientPath() + "netclient.yml")
}

func ConvertNode(s *models.Node) *Node {
	//pretty.Println(s)
	var n Node
	n.ID = s.ID
	n.Name = s.Name
	n.Network = s.Network
	n.Password = s.Password
	n.AccessKey = s.AccessKey
	n.NetworkRange = ToIPNet(s.NetworkSettings.AddressRange)
	n.NetworkRange6 = ToIPNet(s.NetworkSettings.AddressRange6)
	n.InternetGateway = ToUDPAddr(s.InternetGateway)
	n.Interface = s.Interface
	n.Server = strings.Replace(s.Server, "api.", "", 1)
	n.TrafficKeys = s.TrafficKeys
	n.Endpoint = ToIPNet(s.Endpoint)
	n.Connected, _ = strconv.ParseBool(s.Connected)
	n.MacAddress, _ = net.ParseMAC(s.MacAddress)
	n.Port = int(s.ListenPort)
	n.Address.IP = net.ParseIP(s.Address)
	n.Address.Mask = n.NetworkRange.Mask
	n.Address6.IP = net.ParseIP(s.Address6)
	n.Address6.Mask = n.NetworkRange6.Mask
	n.ListenPort = int(s.ListenPort)
	n.LocalAddress = ToIPNet(s.LocalAddress)
	n.LocalRange = ToIPNet(s.LocalRange)
	n.MTU = int(s.MTU)
	n.PersistentKeepalive = int(s.PersistentKeepalive)
	n.PublicKey, _ = wgtypes.ParseKey(s.PublicKey)
	n.PostUp = s.PostUp
	n.PostDown = s.PostDown
	n.Action = s.Action
	n.UDPHolePunch, _ = strconv.ParseBool(s.UDPHolePunch)
	n.IsLocal, _ = strconv.ParseBool(s.IsLocal)
	n.IsEgressGateway, _ = strconv.ParseBool(s.IsEgressGateway)
	n.IsIngressGateway, _ = strconv.ParseBool(s.IsIngressGateway)
	n.IsStatic, _ = strconv.ParseBool(s.IsStatic)
	n.IsPending, _ = strconv.ParseBool(s.IsPending)
	n.DNSOn, _ = strconv.ParseBool(s.DNSOn)
	n.IsHub, _ = strconv.ParseBool(s.IsHub)
	return &n
}

func ConvertToOldNode(n *Node) *models.Node {
	var s models.Node
	s.ID = n.ID
	s.Name = n.Name
	s.Network = n.Network
	s.Password = n.Password
	s.AccessKey = n.AccessKey
	s.NetworkSettings.AddressRange = n.NetworkRange.String()
	s.NetworkSettings.AddressRange6 = n.NetworkRange6.String()
	s.InternetGateway = n.InternetGateway.String()
	s.Interface = n.Interface
	s.Server = n.Server
	s.TrafficKeys = n.TrafficKeys
	s.Endpoint = n.Endpoint.String()
	s.Connected = strconv.FormatBool(n.Connected)
	s.MacAddress = n.MacAddress.String()
	s.ListenPort = int32(n.ListenPort)
	s.Address = n.Address.String()
	s.Address6 = n.Address6.String()
	s.ListenPort = int32(n.ListenPort)
	s.LocalAddress = n.LocalAddress.String()
	s.LocalRange = n.LocalRange.String()
	s.MTU = int32(n.MTU)
	s.PersistentKeepalive = int32(s.PersistentKeepalive)
	s.PublicKey = n.PublicKey.String()
	s.PostUp = n.PostUp
	s.PostDown = n.PostDown
	s.Action = n.Action
	s.UDPHolePunch = FormatBool(n.UDPHolePunch)
	s.IsLocal = FormatBool(n.IsLocal)
	s.IsEgressGateway = FormatBool(n.IsEgressGateway)
	s.IsIngressGateway = FormatBool(n.IsIngressGateway)
	s.IsStatic = FormatBool(n.IsStatic)
	s.IsPending = FormatBool(n.IsPending)
	s.DNSOn = FormatBool(n.DNSOn)
	s.IsHub = FormatBool(n.IsHub)
	return &s
}

func ToIPNet(cidr string) net.IPNet {
	_, response, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}
	}
	return *response
}

func ToUDPAddr(address string) *net.UDPAddr {
	addr, _ := net.ResolveUDPAddr("udp", address)
	return addr
}

func WriteInitialServerConfig(cfg *models.ServerConfig, id, pass string) error {
	var s Server
	s.Name = strings.Replace(cfg.Server, "broker.", "", 1)
	s.Broker = cfg.Server
	s.MQPort = cfg.MQPort
	s.API = cfg.API
	s.MQID = id
	s.Password = pass
	s.DNSMode, _ = strconv.ParseBool(cfg.DNSMode)
	s.CoreDNSAddr = cfg.CoreDNSAddr
	s.Version = cfg.Version
	s.Is_EE = cfg.Is_EE
	Servers[s.Name] = s
	log.Println("server to be saved", s.Name)
	pretty.Println(Servers[s.Name])
	return WriteServerConfig()
}

func SaveBackups(network string) error {
	input := GetNetclientNodePath() + network + ".yml"
	back := input + ".bak"
	if err := copyFile(input, back); err != nil {
		log.Println("copyfile err 1")
		return err
	}
	n, err := ReadConfig(network)
	if err != nil {
		log.Println("readNodeConfig", err)
		return err
	}
	input = GetNetclientServerPath() + n.Server
	back = input + ".bak"
	if err := copyFile(input, back); err != nil {
		log.Println("copyfile err 2")
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
		return WINDOWS_APP_DATA_PATH + "nodes\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "nodes/"
	} else {
		return LINUX_APP_DATA_PATH + "nodes/"
	}
}

// GetNetclientServerPath - gets path to netclient server configuration files
func GetNetclientServerPath() string {
	if runtime.GOOS == "windows" {
		return WINDOWS_APP_DATA_PATH + "servers\\"
	} else if runtime.GOOS == "darwin" {
		return MAC_APP_DATA_PATH + "servers/"
	} else {
		return LINUX_APP_DATA_PATH + "servers/"
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

func fileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ParseAccessToken - used to parse the base64 encoded access token
func ParseAccessToken(token string) (*models.AccessToken, error) {
	tokenbytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		logger.Log(0, "error decoding token", err.Error())
		return nil, err
	}
	var accesstoken models.AccessToken
	if err := json.Unmarshal(tokenbytes, &accesstoken); err != nil {
		logger.Log(0, "error decoding token", err.Error())
		return nil, err
	}
	return &accesstoken, nil
}

func ParseJoinFlags(cmd *cobra.Command, node *Node, netclient *Config, server *Server) {
	temp, _ := cmd.Flags().GetString("address")
	node.Address = ToIPNet(temp)
	temp, _ = cmd.Flags().GetString("address6")
	node.Address6 = ToIPNet(temp)
	node.DNSOn, _ = cmd.Flags().GetBool("dnson")
	temp, _ = cmd.Flags().GetString("endpoint")
	node.Endpoint = ToIPNet(temp)
	netclient.IPForwarding, _ = cmd.Flags().GetBool("ipforwarding")
	node.Interface, _ = cmd.Flags().GetString("interface")
	node.IsLocal, _ = cmd.Flags().GetBool("islocal")
	node.PersistentKeepalive, _ = cmd.Flags().GetInt("keepalive")
	node.AccessKey, _ = cmd.Flags().GetString("key")
	temp, _ = cmd.Flags().GetString("localaddress")
	node.LocalAddress = ToIPNet(temp)
	temp, _ = cmd.Flags().GetString("macaddress")
	node.MacAddress, _ = net.ParseMAC(temp)
	node.Name, _ = cmd.Flags().GetString("name")
	node.Network, _ = cmd.Flags().GetString("network")
	node.Password, _ = cmd.Flags().GetString("password")
	node.Port, _ = cmd.Flags().GetInt("port")
}

// ReplaceWithBackup - replaces netconfig file with backup
func ReplaceWithBackup(network string) error {
	var backupPath = GetNetclientNodePath() + network + ".yml.back"
	var configPath = GetNetclientNodePath() + network + ".yml"
	if FileExists(backupPath) {
		input, err := os.ReadFile(backupPath)
		if err != nil {
			logger.Log(0, "failed to read file ", backupPath, " to backup network: ", network)
			return err
		}
		if err = os.WriteFile(configPath, input, 0600); err != nil {
			logger.Log(0, "failed backup ", backupPath, " to ", configPath)
			return err
		}
	}
	logger.Log(0, "used backup file for network: ", network)
	return nil
}

// FileExists - checks if a file exists on disk
func FileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// GetSystemNetworks - get networks locally
func GetSystemNetworks() []string {
	var networks []string
	if len(Nodes) == 0 {
		GetNodes()
	}
	for k := range Nodes {
		networks = append(networks, k)
	}
	return networks
}

// GetServers - return list of servers
func GetServerList() []string {
	var servers []string
	for k := range Servers {
		servers = append(servers, k)
	}
	return servers
}

// ModPort - Change Node Port if UDP Hole Punching or ListenPort is not free
func ModPort(node *Node) error {
	var err error
	if node.UDPHolePunch {
		node.ListenPort = 0
	} else {
		node.ListenPort, err = ncutils.GetFreePort(node.ListenPort)
	}
	return err
}

func FormatBool(b bool) string {
	s := "no"
	if b {
		s = "yes"
	}
	return s
}
