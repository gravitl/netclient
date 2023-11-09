// Package config provides functions for reading the config.
package config

import (
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

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
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

const (
	UnKnown InitType = iota
	Systemd
	SysVInit
	Runit
	OpenRC
	Initd
)

// Initype - the type of init system in use
type InitType int

// String - returns the string representation of the init type
func (i InitType) String() string {
	return [...]string{"unknown", "systemd", "sysvinit", "runit", "openrc", "initd"}[i]
}

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
	// FwClose - firewall manager shutdown func
	FwClose func() = func() {}
	// WgPublicListenPort - host's wireguard public listen port
	WgPublicListenPort int
	// HostPublicIP - host's public endpoint
	HostPublicIP net.IP
	// HostNatType - host's NAT type
	HostNatType string
)

// Config configuration for netclient and host as a whole
type Config struct {
	models.Host
	PrivateKey        wgtypes.Key          `json:"privatekey" yaml:"privatekey"`
	TrafficKeyPrivate []byte               `json:"traffickeyprivate" yaml:"traffickeyprivate"`
	HostPeers         []wgtypes.PeerConfig `json:"host_peers" yaml:"host_peers"`
	DisableGUIServer  bool                 `json:"disableguiserver" yaml:"disableguiserver"`
	InitType          InitType             `json:"inittype" yaml:"inittype"`
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)
}

// UpdateNetcllient updates the in memory version of the host configuration
func UpdateNetclient(c Config) {
	logger.Verbosity = c.Verbosity
	logger.Log(3, "Logging verbosity updated to", strconv.Itoa(logger.Verbosity))
	netclient = c
}

func UpdateHost(host *models.Host) (resetInterface, restart, sendHostUpdate bool) {
	hostCfg := Netclient()
	if hostCfg == nil || host == nil {
		return
	}
	if host.ListenPort != 0 && hostCfg.ListenPort != host.ListenPort {
		// check if new port is free, otherwise don't update
		if !ncutils.IsPortFree(host.ListenPort) {
			// send the host update to server with actual port on the interface
			host.ListenPort = hostCfg.ListenPort
			sendHostUpdate = true
		}
		restart = true
	}
	if host.MTU != 0 && hostCfg.MTU != host.MTU {
		resetInterface = true
	}
	// do not update fields that should not be changed by server
	host.OS = hostCfg.OS
	host.FirewallInUse = hostCfg.FirewallInUse
	host.DaemonInstalled = hostCfg.DaemonInstalled
	host.ID = hostCfg.ID
	host.Version = hostCfg.Version
	host.MacAddress = hostCfg.MacAddress
	host.PublicKey = hostCfg.PublicKey
	host.TrafficKeyPublic = hostCfg.TrafficKeyPublic
	// don't update any public ports coming from server,overwrite the values
	host.WgPublicListenPort = hostCfg.WgPublicListenPort
	// store password before updating
	host.HostPass = hostCfg.HostPass
	hostCfg.Host = *host
	UpdateNetclient(*hostCfg)
	WriteNetclientConfig()
	return
}

// Netclient returns a pointer to the im memory version of the host configuration
func Netclient() *Config {
	return &netclient
}

// UpdateHostPeers - updates host peer map in the netclient config
func UpdateHostPeers(peers []wgtypes.PeerConfig) (isHostInetGW bool) {
	netclient.HostPeers = peers
	return detectOrFilterGWPeers(peers)
}

// DeleteServerHostPeerCfg - deletes the host peers for the server
func DeleteServerHostPeerCfg() {
	netclient.HostPeers = []wgtypes.PeerConfig{}
}

// RemoveServerHostPeerCfg - sets remove flag for all peers on the given server peers
func RemoveServerHostPeerCfg() {
	if netclient.HostPeers == nil {
		netclient.HostPeers = []wgtypes.PeerConfig{}
		return
	}
	peers := netclient.HostPeers
	for i := range peers {
		peer := peers[i]
		peer.Remove = true
		peers[i] = peer
	}
	netclient.HostPeers = peers
	_ = WriteNetclientConfig()
}

// SetVersion - sets version for use by other packages
func SetVersion(ver string) {
	Version = ver
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
	netclient = Config{}
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
			if err := os.MkdirAll(GetNetclientPath(), os.ModePerm); err != nil {
				logger.Log(0, "error creating netclient config directory", err.Error())
			}
			if err := os.Chmod(GetNetclientPath(), 0775); err != nil {
				logger.Log(0, "error setting permissions on netclient config directory", err.Error())
			}
		} else if err != nil {
			return err
		}
	}
	if Lock(lockfile) != nil {
		return errors.New("failed to obtain lockfile")
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
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
			if err != nil || len(bytes) == 0 {
				_ = os.Remove(lockfile)
			} else {
				var owner int
				if err := json.Unmarshal(bytes, &owner); err != nil {
					_ = os.Remove(lockfile)
				} else {
					if IsPidDead(owner) {
						if err := os.Remove(lockfile); err != nil && debug {
							logger.Log(0, "error removing lockfile", err.Error())
						}
					}
				}
			}
		} else {
			bytes, _ := json.Marshal(pid)
			if err := os.WriteFile(lockfile, bytes, os.ModePerm); err != nil && debug {
				logger.Log(0, "unable to write to lockfile: ", err.Error())
			} else {
				return nil
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
				logger.Log(0, "error reading file", err.Error())
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
					if err := os.Remove(lockfile); err != nil && debug {
						logger.Log(0, "error removing lockfile", err.Error())
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

func detectOrFilterGWPeers(peers []wgtypes.PeerConfig) bool {
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
	clientPeers := netclient.HostPeers
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

	serverNodes := GetNodes()
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
