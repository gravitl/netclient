// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

var (
	// Netclient contains the netclient config
	netclient Config
	// Version - default version string
	Version = "dev"
)

// Config configuration for netclient and host as a whole
type Config struct {
	models.Host
	PrivateKey        wgtypes.Key                     `json:"privatekey" yaml:"privatekey"`
	MacAddress        net.HardwareAddr                `json:"macaddress" yaml:"macaddress"`
	TrafficKeyPrivate []byte                          `json:"traffickeyprivate" yaml:"traffickeyprivate"`
	TrafficKeyPublic  []byte                          `json:"traffickeypublic" yaml:"trafficekeypublic"`
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
	netclient = c
}

// Netclient returns a pointer to the im memory version of the host configuration
func Netclient() *Config {
	return &netclient
}

// GetHostPeerList - gets the combined list of peers for the host
func GetHostPeerList() (allPeers []wgtypes.PeerConfig) {

	peerMap := make(map[string]int)
	for _, serverPeers := range netclient.HostPeers {
		for i, peerI := range serverPeers {
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
func UpdateHostPeers(server string, peers []wgtypes.PeerConfig) {
	hostPeerMap := netclient.HostPeers
	if hostPeerMap == nil {
		hostPeerMap = make(map[string][]wgtypes.PeerConfig)
	}
	hostPeerMap[server] = peers
	netclient.HostPeers = hostPeerMap
}

// DeleteServerHostPeerCfg - deletes the host peers for the server
func DeleteServerHostPeerCfg(server string) {
	if netclient.HostPeers == nil {
		netclient.HostPeers = make(map[string][]wgtypes.PeerConfig)
		return
	}
	delete(netclient.HostPeers, server)
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

// ReadNetclientConfig loads the host configuration into memory.
func ReadNetclientConfig() error {
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	file := GetNetclientPath() + "netclient.yml"
	if err := Lock(lockfile); err != nil {
		logger.Log(0, "unable to obtain lockfile for host config", err.Error())
		return err
	}
	defer Unlock(lockfile)
	f, err := os.Open(file)
	if err != nil {
		logger.Log(0, "failed to open host config", err.Error())
		return err
	}
	if err := yaml.NewDecoder(f).Decode(&netclient); err != nil {
		logger.Log(0, "failed to decode host config", err.Error())
	}
	return nil
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
				if debug {
					logger.Log(0, "error unmarhalling data from lockfile", err.Error())
				}
			}
			if debug {
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

// RefreshConfigs refreshes in-memory data with latest disk data
func RefreshConfigs() error {
	if err := ReadNetclientConfig(); err != nil {
		return err
	}
	if err := ReadNodeConfig(); err != nil {
		return err
	}
	if err := ReadServerConf(); err != nil {
		return err
	}
	return nil
}
