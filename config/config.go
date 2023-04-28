// Package config provides functions for reading the config.
package config

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

const (
	// LinuxAppDataPath - linux path
	LinuxAppDataPath = "/etc/netclient/"
	// MacAppDataPath - mac path
	MacAppDataPath = "/Applications/Netclient/"
	// WindowsAppDataPath - windows path
	WindowsAppDataPath = "C:\\Program Files (x86)\\Netclient\\"
	// Timeout timelimit for obtaining/releasing lockfile
	Timeout = time.Second * 5
	// ConfigLockfile lockfile to control access to config file
	ConfigLockfile = "config.lck"
	// MaxNameLength maximum length of a node name
	MaxNameLength = 62
	// DefaultListenPort default port for wireguard
	DefaultListenPort = 51821
	// DefaultMTU default MTU for wireguard
	DefaultMTU = 1420
)

var (
	netclient Config // netclient contains the netclient config
	// Version - default version string
	Version = "dev"
	// GW4PeerDetected - indicates if an IPv4 gwPeer (0.0.0.0/0) was found
	GW4PeerDetected bool
	// GW4Addr - the peer's address for IPv4 gateways
	GW4Addr net.IPNet
	// GW6PeerDetected - indicates if an IPv6 gwPeer (::/0) was found, currently unused
	GW6PeerDetected bool
	// GW6Addr - the peer's address for IPv6 gateways
	GW6Addr net.IPNet
)

// Config configuration for netclient and host as a whole
type Config struct {
	models.Host
	PrivateKey        wgtypes.Key                     `json:"privatekey" yaml:"privatekey"`
	TrafficKeyPrivate []byte                          `json:"traffickeyprivate" yaml:"traffickeyprivate"`
	InternetGateway   net.UDPAddr                     `json:"internetgateway" yaml:"internetgateway"`
	HostPeers         map[string][]wgtypes.PeerConfig `json:"peers" yaml:"peers"`
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)
	netclient.HostPeers = make(map[string][]wgtypes.PeerConfig)
}

// UpdateNetcllient updates the in memory version of the host configuration
func UpdateNetclient(c Config) {
	logger.Verbosity = c.Verbosity
	logger.Log(3, "Logging verbosity updated to", strconv.Itoa(logger.Verbosity))
	netclient = c
}

// UpdateHost - update host with data from server
func UpdateHost(newHost *models.Host) {
	netclient.Host.Name = newHost.Name
	netclient.Host.Verbosity = newHost.Verbosity
	netclient.Host.MTU = newHost.MTU
	if newHost.ListenPort > 0 {
		netclient.Host.ListenPort = newHost.ListenPort
	}
	if newHost.ProxyListenPort > 0 {
		netclient.Host.ProxyListenPort = newHost.ProxyListenPort
	}
	netclient.Host.IsDefault = newHost.IsDefault
	netclient.Host.DefaultInterface = newHost.DefaultInterface
	// only update proxy enabled if it hasn't been modified by another server
	if !netclient.Host.ProxyEnabledSet {
		netclient.Host.ProxyEnabled = newHost.ProxyEnabled
		netclient.Host.ProxyEnabledSet = true
	}
	netclient.Host.IsStatic = newHost.IsStatic
	if err := WriteNetclientConfig(); err != nil {
		logger.Log(0, "error updating netclient config after update", err.Error())
	}
}

// Netclient returns a pointer to the im memory version of the host configuration
func Netclient() *Config {
	return &netclient
}

// GetHostPeerList - gets the combined list of peers for the host
func GetHostPeerList() (allPeers []wgtypes.PeerConfig) {
	hostPeerMap := netclient.HostPeers
	peerMap := make(map[string]int)
	for _, serverPeers := range hostPeerMap {
		serverPeers := serverPeers
		for i, peerI := range serverPeers {
			peerI := peerI
			if ind, ok := peerMap[peerI.PublicKey.String()]; ok {
				allPeers[ind].AllowedIPs = getUniqueAllowedIPList(allPeers[ind].AllowedIPs, peerI.AllowedIPs)
			} else {
				peerMap[peerI.PublicKey.String()] = i
				allPeers = append(allPeers, peerI)
			}

		}
	}
	return
}

// UpdateHostPeers - updates host peer map in the netclient config
func UpdateHostPeers(server string, peers []wgtypes.PeerConfig) (isHostInetGW bool) {
	hostPeerMap := netclient.HostPeers
	if hostPeerMap == nil {
		hostPeerMap = make(map[string][]wgtypes.PeerConfig, 1)
	}
	hostPeerMap[server] = peers
	netclient.HostPeers = hostPeerMap
	return detectOrFilterGWPeers(server, peers)
}

// DeleteServerHostPeerCfg - deletes the host peers for the server
func DeleteServerHostPeerCfg(server string) {
	if netclient.HostPeers == nil {
		netclient.HostPeers = make(map[string][]wgtypes.PeerConfig)
		return
	}
	delete(netclient.HostPeers, server)
}

// RemoveServerHostPeerCfg - sets remove flag for all peers on the given server peers
func RemoveServerHostPeerCfg(serverName string) {
	if netclient.HostPeers == nil {
		netclient.HostPeers = make(map[string][]wgtypes.PeerConfig)
		return
	}
	peers := netclient.HostPeers[serverName]
	for i := range peers {
		peer := peers[i]
		peer.Remove = true
		peers[i] = peer
	}
	netclient.HostPeers[serverName] = peers
	_ = WriteNetclientConfig()
}

func getUniqueAllowedIPList(currIps, newIps []net.IPNet) []net.IPNet {
	uniqueIpList := []net.IPNet{}
	ipMap := make(map[string]struct{})
	uniqueIpList = append(uniqueIpList, currIps...)
	uniqueIpList = append(uniqueIpList, newIps...)
	for i := len(uniqueIpList) - 1; i >= 0; i-- {
		if _, ok := ipMap[uniqueIpList[i].String()]; ok {
			// if ip already exists, remove duplicate one
			uniqueIpList = append(uniqueIpList[:i], uniqueIpList[i+1:]...)
		} else {
			ipMap[uniqueIpList[i].String()] = struct{}{}
		}
	}
	return uniqueIpList
}

// SetVersion - sets version for use by other packages
func SetVersion(ver string) {
	Version = ver
}

// setLogVerbosity sets the logger verbosity from config
func setLogVerbosity(flags *viper.Viper) {
	verbosity := flags.GetInt("verbosity")
	if netclient.Verbosity > verbosity {
		logger.Verbosity = netclient.Verbosity
		return
	}
	logger.Verbosity = verbosity
}

// ReadNetclientConfig reads the host configuration file and returns it as an instance.
func ReadNetclientConfig() (*Config, error) {
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	file := GetNetclientPath() + "netclient.yml"
	if err := Lock(lockfile); err != nil {
		return nil, err
	}
	defer Unlock(lockfile)
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&netclient); err != nil {
		return nil, err
	}
	return &netclient, nil
}

// WriteNetclientConfiig writes the in memory host configuration to disk
func WriteNetclientConfig() error {
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	file := GetNetclientPath() + "netclient.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(GetNetclientPath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	if Lock(lockfile) != nil {
		return errors.New("failed to obtain lockfile")
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(netclient)
	if err != nil {
		return err
	}
	return f.Sync()
}

// GetNetclientPath - returns path to netclient config directory
func GetNetclientPath() string {
	if runtime.GOOS == "windows" {
		return WindowsAppDataPath
	} else if runtime.GOOS == "darwin" {
		return MacAppDataPath
	} else {
		return LinuxAppDataPath
	}
}

// GetNetclientInstallPath returns the full path where netclient should be installed based on OS
func GetNetclientInstallPath() string {
	switch runtime.GOOS {
	case "windows":
		return GetNetclientPath() + "netclient.exe"
	case "macos":
		return "/usr/local/bin/netclient"
	default:
		return "/usr/bin/netclient"
	}
}

// Lock creates a lockfile with pid as contents
// if lockfile exists but belongs to defunct process
// the existing lockfile will be deleted and new one created
// if unable to create within TIMEOUT returns error
func Lock(lockfile string) error {
	debug := netclient.Debug
	start := time.Now()
	pid := os.Getpid()
	if debug {
		logger.Log(0, "lock try")
	}
	for {
		if _, err := os.Stat(lockfile); !errors.Is(err, os.ErrNotExist) {
			if debug {
				logger.Log(0, "file exists")
			}
			bytes, err := os.ReadFile(lockfile)
			if err == nil {
				var owner int
				if json.Unmarshal(bytes, &owner) == nil {
					if IsPidDead(owner) {
						if err := os.Remove(lockfile); err != nil {
							if debug {
								logger.Log(0, "error removing lockfile", err.Error())
							}
						}
					}
				}
			} else if debug {
				logger.Log(0, "error reading lockfile", err.Error())
			}
		} else {
			bytes, _ := json.Marshal(pid)
			if err := os.WriteFile(lockfile, bytes, os.ModePerm); err == nil {
				if debug {
					logger.Log(0, "file locked")
				}
				return nil
			} else {
				if debug {
					logger.Log(0, "unable to write: ", err.Error())
				}
			}
		}
		if debug {
			logger.Log(0, "unable to get lock")
		}
		if time.Since(start) > Timeout {
			return errors.New("TIMEOUT")
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// Unlock removes a lockfile if contents of lockfile match current pid
// also removes lockfile if owner process is no longer running
// will return TIMEOUT error if timeout exceeded
func Unlock(lockfile string) error {
	var pid int
	debug := netclient.Debug
	start := time.Now()
	if debug {
		logger.Log(0, "unlock try")
	}
	for {
		bytes, err := os.ReadFile(lockfile)
		if err != nil {

			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if debug {
				logger.Log(0, "error reading file")
			}
			return err
		}
		if debug {
			logger.Log(0, "lockfile exists")
		}
		if err := json.Unmarshal(bytes, &pid); err == nil {
			if pid == os.Getpid() {
				if err := os.Remove(lockfile); err == nil {
					if debug {
						logger.Log(0, "removed lockfile")

					}
					return nil
				} else {
					if debug {
						logger.Log(0, "error removing file", err.Error())
					}
				}
			} else {
				if debug {
					logger.Log(0, "wrong pid")
				}
				if IsPidDead(pid) {
					if err := os.Remove(lockfile); err != nil {
						if debug {
							logger.Log(0, "error removing lockfile", err.Error())
						}
					}
				}
			}
		} else {
			if debug {
				logger.Log(0, "unmarshal err ", err.Error())
			}
		}
		if debug {
			logger.Log(0, "unable to unlock")
		}
		if time.Since(start) > Timeout {
			return errors.New("TIMEOUT")
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// IsPidDead checks if given pid is not running
func IsPidDead(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	//FindProcess always returns err = nil on linux
	err = process.Signal(syscall.Signal(0))
	return errors.Is(err, os.ErrProcessDone)
}

// FormatName ensures name is in character set and is proper length
// Sets name to blank on failure
func FormatName(name string) string {
	if !InCharSet(name) {
		name = ncutils.DNSFormatString(name)
	}
	if len(name) > MaxNameLength {
		name = ncutils.ShortenString(name, MaxNameLength)
	}
	if !InCharSet(name) || len(name) > MaxNameLength {
		logger.Log(1, "could not properly format name, setting to blank")
		name = ""
	}
	return name
}

// InCharSet verifies if all chars in string are part of defined charset
func InCharSet(name string) bool {
	charset := "abcdefghijklmnopqrstuvwxyz1234567890-"
	for _, char := range name {
		if !strings.Contains(charset, strings.ToLower(string(char))) {
			return false
		}
	}
	return true
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(viper *viper.Viper) {
	checkUID()
	ReadNetclientConfig()
	setLogVerbosity(viper)
	ReadNodeConfig()
	ReadServerConf()
	CheckConfig()
	//check netclient dirs exist
	if _, err := os.Stat(GetNetclientPath()); err != nil {
		if os.IsNotExist(err) {
			if err := os.Mkdir(GetNetclientPath(), os.ModePerm); err != nil {
				logger.Log(0, "failed to create dirs", err.Error())
			}
		} else {
			logger.FatalLog("could not create /etc/netclient dir" + err.Error())
		}
	}
	//wireguard.WriteWgConfig(Netclient(), GetNodes())
}

// CheckConfig - verifies and updates configuration settings
func CheckConfig() {
	fail := false
	saveRequired := false
	netclient := Netclient()
	if netclient.OS != runtime.GOOS {
		logger.Log(0, "setting OS")
		netclient.OS = runtime.GOOS
		saveRequired = true
	}
	if netclient.Version != Version {
		logger.Log(0, "setting version")
		netclient.Version = Version
		saveRequired = true
	}
	netclient.IPForwarding = true
	if netclient.ID == uuid.Nil {
		logger.Log(0, "setting netclient hostid")
		netclient.ID = uuid.New()
		netclient.HostPass = ncutils.MakeRandomString(32)
		saveRequired = true
	}
	if netclient.Name == "" {
		logger.Log(0, "setting name")
		netclient.Name, _ = os.Hostname()
		//make sure hostname is suitable
		netclient.Name = FormatName(netclient.Name)
		saveRequired = true
	}
	if netclient.MacAddress == nil {
		logger.Log(0, "setting macAddress")
		mac, err := ncutils.GetMacAddr()
		if err != nil {
			logger.FatalLog("failed to set macaddress", err.Error())
		}
		netclient.MacAddress = mac[0]
		if runtime.GOOS == "darwin" && netclient.MacAddress.String() == "ac:de:48:00:11:22" {
			if len(mac) > 1 {
				netclient.MacAddress = mac[1]
			} else {
				netclient.MacAddress = ncutils.RandomMacAddress()
			}
		}
		saveRequired = true
	}
	if (netclient.PrivateKey == wgtypes.Key{}) {
		logger.Log(0, "setting wireguard keys")
		var err error
		netclient.PrivateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.FatalLog("failed to generate wg key", err.Error())
		}
		netclient.PublicKey = netclient.PrivateKey.PublicKey()
		saveRequired = true
	}
	if netclient.Interface == "" {
		logger.Log(0, "setting wireguard interface")
		netclient.Interface = models.WIREGUARD_INTERFACE
		saveRequired = true
	}
	if netclient.ListenPort == 0 {
		logger.Log(0, "setting listenport")
		port, err := ncutils.GetFreePort(DefaultListenPort)
		if err != nil {
			logger.Log(0, "error getting free port", err.Error())
		} else {
			netclient.ListenPort = port
			saveRequired = true
		}
	}
	if netclient.ProxyListenPort == 0 {
		logger.Log(0, "setting proxyListenPort")
		port, err := ncutils.GetFreePort(models.NmProxyPort)
		if err != nil {
			logger.Log(0, "error getting free port", err.Error())
		} else {
			netclient.ProxyListenPort = port
			saveRequired = true
		}
	}
	if netclient.MTU == 0 {
		logger.Log(0, "setting MTU")
		netclient.MTU = DefaultMTU
	}

	if len(netclient.TrafficKeyPrivate) == 0 {
		logger.Log(0, "setting traffic keys")
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			logger.FatalLog("error generating traffic keys", err.Error())
		}
		bytes, err := ncutils.ConvertKeyToBytes(priv)
		if err != nil {
			logger.FatalLog("error generating traffic keys", err.Error())
		}
		netclient.TrafficKeyPrivate = bytes
		bytes, err = ncutils.ConvertKeyToBytes(pub)
		if err != nil {
			logger.FatalLog("error generating traffic keys", err.Error())
		}
		netclient.TrafficKeyPublic = bytes
		saveRequired = true
	}
	// check for nftables present if on Linux
	if FirewallHasChanged() {
		saveRequired = true
		SetFirewall()
	}
	if !ncutils.FileExists(GetNetclientPath() + "netmaker.conf") {
		if err := os.MkdirAll(GetNetclientPath(), os.ModePerm); err != nil {
			logger.Log(0, "failed to create /etc/netclient", err.Error())
		}
		if _, err := os.Create(GetNetclientPath() + "netmaker.conf"); err != nil {
			logger.Log(0, "failed to create netmaker.conf: ", err.Error())
		}
	}
	if saveRequired {
		logger.Log(3, "saving netclient configuration")
		if err := WriteNetclientConfig(); err != nil {
			logger.FatalLog("could not save netclient config " + err.Error())
		}
	}
	_ = ReadServerConf()
	for _, server := range Servers {
		if server.MQID != netclient.ID {
			fail = true
			logger.Log(0, server.Name, "is misconfigured: MQID/Password does not match hostid/password")
		}
	}
	_ = ReadNodeConfig()
	nodes := GetNodes()
	for _, node := range nodes {
		//make sure server config exists
		server := GetServer(node.Server)
		if server == nil {
			fail = true
			logger.Log(0, "configuration for", node.Server, "is missing")
		}
	}
	if fail {
		logger.FatalLog("configuration is invalid, fix before proceeding")
	}
}

// Convert converts netclient host/node struct to netmaker host/node structs
func Convert(h *Config, n *Node) (models.Host, models.Node) {
	var host models.Host
	var node models.Node
	temp, err := json.Marshal(h)
	if err != nil {
		logger.Log(0, "host marshal error", h.Name, err.Error())
	}
	if err := json.Unmarshal(temp, &host); err != nil {
		logger.Log(0, "host unmarshal err", h.Name, err.Error())
	}
	temp, err = json.Marshal(n)
	if err != nil {
		logger.Log(0, "node marshal error", h.Name, err.Error())
	}
	if err := json.Unmarshal(temp, &node); err != nil {
		logger.Log(0, "node unmarshal err", h.Name, err.Error())
	}
	return host, node
}

func detectOrFilterGWPeers(server string, peers []wgtypes.PeerConfig) bool {
	isInetGW := IsHostInetGateway()
	if len(peers) > 0 {
		if GW4PeerDetected || GW6PeerDetected { // check if there is a change in GWs before proceeding
			for i := range peers {
				peer := peers[i]
				if peerHasIp(&GW4Addr, peer.AllowedIPs[:]) && peer.Remove { // Indicates a removal of current gw, set detected to false to recalc
					GW4PeerDetected = false
					break
				} else if peerHasIp(&GW6Addr, peer.AllowedIPs[:]) { // TODO (IPv6)
					GW6PeerDetected = false
					break
				}
			}
		}
	}
	clientPeers := GetHostPeerList()
	var foundGW4Again, foundGW6Again bool
	if len(clientPeers) > 0 {
		for i := range clientPeers {
			peer := clientPeers[i]
			for j := range peer.AllowedIPs {
				ip := peer.AllowedIPs[j]
				if ip.String() == "0.0.0.0/0" { // handle IPv4
					if isInetGW || peer.Remove { // skip allowed and removed peers IPs for internet gws
						continue
					}
					if !GW4PeerDetected && j > 0 {
						GW4PeerDetected = true
						foundGW4Again = true
						GW4Addr = peer.AllowedIPs[j-1]
					} else if peerHasIp(&GW4Addr, peer.AllowedIPs[:]) {
						foundGW4Again = true
					}
				} else if ip.String() == "::/0" { // handle IPv6
					if isInetGW || peer.Remove { // skip allowed IPs for internet gws
						continue
					}
					if !GW6PeerDetected && j > 0 {
						GW6PeerDetected = true
						foundGW6Again = true
						GW6Addr = peer.AllowedIPs[j-1]
					} else if peerHasIp(&ip, peer.AllowedIPs[:]) {
						foundGW6Again = true
					}
				}
			}
		}
	}
	GW4PeerDetected = foundGW4Again
	GW6PeerDetected = foundGW6Again

	return isInetGW
}

func peerHasIp(ip *net.IPNet, allowedIPs []net.IPNet) bool {
	if ip == nil {
		return false
	}
	for i := range allowedIPs {
		if ip.Contains(allowedIPs[i].IP) {
			return true
		}
	}
	return false
}

// IsHostInetGateway - checks, based on netclient memory,
// if current client is an internet gateway
func IsHostInetGateway() bool {
	servers := GetServers()
	for i := range servers {
		serverName := servers[i]
		serverNodes := GetNodesByServer(serverName)
		for j := range serverNodes {
			serverNode := serverNodes[j]
			if serverNode.IsEgressGateway {
				for _, egressRange := range serverNode.EgressGatewayRanges {
					if egressRange == "0.0.0.0/0" || egressRange == "::/0" {
						return true
					}
				}
			}
		}
	}
	return false
}

// setFirewall - determine and record firewall in use
func SetFirewall() {
	if ncutils.IsLinux() {
		if ncutils.IsIPTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_IPTABLES
		} else if ncutils.IsNFTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_NFTABLES
		} else {
			netclient.FirewallInUse = models.FIREWALL_NONE
		}
	} else {
		netclient.FirewallInUse = models.FIREWALL_NONE
	}
}

// FirewallHasChanged - checks if the firewall has changed
func FirewallHasChanged() bool {
	if netclient.FirewallInUse == models.FIREWALL_NONE && !ncutils.IsLinux() {
		return false
	}
	if netclient.FirewallInUse == models.FIREWALL_IPTABLES && ncutils.IsIPTablesPresent() {
		return false
	}
	if netclient.FirewallInUse == models.FIREWALL_NFTABLES && ncutils.IsNFTablesPresent() {
		return false
	}
	return true
}
