// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/viper"
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
)

var (
	// Netclient contains the netclient config
	Netclient Config
	// Version - default version string
	Version = "dev"
)

// Config configuration for netclient and host as a whole
type Config struct {
	Verbosity           int `yaml:"verbosity"`
	FirewallInUse       string
	Version             string
	IPForwarding        bool
	DaemonInstalled     bool
	HostID              string
	HostPass            string
	Name                string
	OS                  string
	Debug               bool
	NodePassword        string
	Interface           string
	ListenPort          int
	LocalAddress        net.IPNet
	LocalRange          net.IPNet
	LocalListenPort     int
	MTU                 int
	PersistentKeepalive int
	PrivateKey          wgtypes.Key
	PublicKey           wgtypes.Key
	MacAddress          net.HardwareAddr
	TrafficKeyPrivate   []byte
	TrafficKeyPublic    []byte
}

func init() {
	Servers = make(map[string]Server)
	Nodes = make(map[string]Node)
}

// SetVersion - sets version for use by other packages
func SetVersion(ver string) {
	Version = ver
}

// ReadNetclientConfig reads a configuration file and returns it as an
// instance. If no configuration file is found, nil and no error will be
// returned. The configuration mustID live in one of the directories specified in
// with AddConfigPath()
//
// In case multiple configuration files are found, the one in the most specific
// or "closest" directory will be preferred.
func ReadNetclientConfig() (*Config, error) {
	lockfile := filepath.Join(os.TempDir()) + ConfigLockfile
	viper.SetConfigName("netclient.yml")
	viper.SetConfigType("yml")
	viper.AddConfigPath(GetNetclientPath())
	if err := Lock(lockfile); err != nil {
		return nil, err
	}
	defer Unlock(lockfile)
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

// WriteNetclientConfig save the netclient configuration to disk
func WriteNetclientConfig() error {
	lockfile := filepath.Join(os.TempDir(), ConfigLockfile)
	logger.Log(0, "lock file path: ", lockfile)
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
	err = yaml.NewEncoder(f).Encode(Netclient)
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

// GetNetclientInterfacePath returns path to wireguard interface configuration files
func GetNetclientInterfacePath() string {
	if runtime.GOOS == "windows" {
		return WindowsAppDataPath + "interfaces\\"
	} else if runtime.GOOS == "darwin" {
		return MacAppDataPath + "interfaces/"
	} else {
		return LinuxAppDataPath + "interfaces/"
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

// FileExists - checks if a file exists on disk
func FileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Lock creates a lockfile with pid as contents
// if lockfile exists but belongs to defunct process
// the existing lockfile will be deleted and new one created
// if unable to create within TIMEOUT returns error
func Lock(lockfile string) error {
	debug := Netclient.Debug
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
					logger.Log(0, "unable to write")
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
	debug := Netclient.Debug
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
