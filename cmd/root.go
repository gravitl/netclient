// Package cmd command line for netclient
/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "netclient",
	Short: "Netmaker's netclient agent and CLI",
	Long: `Netmaker's netclient agent and CLI to manage wireguard networks

Join, leave, connect and disconnect from netmaker wireguard networks.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(functions.Migrate, initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().IntP("verbosity", "v", 0, "set logging verbosity 0-4")
	viper.BindPFlags(rootCmd.Flags())

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}

func initConfig() {
	flags := viper.New()
	flags.BindPFlags(rootCmd.Flags())
	InitConfig(flags)
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	nc.Name = "netmaker-test"
	if runtime.GOOS == "darwin" {
		nc.Name = "utun70"
	}
	if err := nc.Create(); err != nil {
		slog.Error("failed to create interface, is wireguard installed?", "error", err)
		os.Exit(1)
	}
	nc.Close()
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(viper *viper.Viper) {
	config.CheckUID()
	config.ReadNetclientConfig()
	setupLogging(viper)
	config.ReadNodeConfig()
	config.ReadServerConf()
	config.SetServerCtx()
	checkConfig()
	//check netclient dirs exist
	if _, err := os.Stat(config.GetNetclientPath()); err != nil {
		if os.IsNotExist(err) {
			if err := os.Mkdir(config.GetNetclientPath(), os.ModePerm); err != nil {
				logger.Log(0, "failed to create dirs", err.Error())
			}
			if err := os.Chmod(config.GetNetclientPath(), 0775); err != nil {
				logger.Log(0, "failed to update permissions of netclient config dir", err.Error())
			}
		} else {
			logger.FatalLog("could not create /etc/netclient dir" + err.Error())
		}
	}
	//wireguard.WriteWgConfig(Netclient(), GetNodes())
}

func setupLogging(flags *viper.Viper) {
	logLevel := &slog.LevelVar{}
	replace := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.SourceKey {
			a.Value = slog.StringValue(filepath.Base(a.Value.String()))
		}
		return a
	}

	// Detect if OS is windows to push slog on Stdout instead of Stderr
	if ncutils.IsWindows() {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: replace, Level: logLevel}))
		slog.SetDefault(logger)
	} else {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, ReplaceAttr: replace, Level: logLevel}))
		slog.SetDefault(logger)
	}

	verbosity := flags.GetInt("verbosity")
	if verbosity > config.Netclient().Verbosity {
		config.Netclient().Verbosity = verbosity
	}
	switch config.Netclient().Verbosity {
	case 4:
		logLevel.Set(slog.LevelDebug)
	case 3:
		logLevel.Set(slog.LevelInfo)
	case 2:
		logLevel.Set(slog.LevelWarn)
	default:
		logLevel.Set(slog.LevelError)
	}
}

// checkConfig - verifies and updates configuration settings
func checkConfig() {
	fail := false
	saveRequired := false
	netclient := config.Netclient()
	if netclient.OS != runtime.GOOS {
		logger.Log(0, "setting OS")
		netclient.OS = runtime.GOOS
		saveRequired = true
	}
	slog.Info("OS is", "os", netclient.OS)
	if netclient.OS == "linux" {
		initType := daemon.GetInitType()
		slog.Debug("init type is", "type", initType.String(), "old type", netclient.InitType.String())
		if netclient.InitType != initType {
			slog.Info("setting init type", "type", initType.String())
			netclient.InitType = initType
			saveRequired = true
		}
	}

	if netclient.Version != config.Version {
		logger.Log(0, "setting version")
		netclient.Version = config.Version
		saveRequired = true
	}
	netclient.IPForwarding = true
	if netclient.ID == uuid.Nil {
		logger.Log(0, "setting netclient hostid")
		netclient.ID = uuid.New()
		netclient.HostPass = ncutils.RandomString(32)
		saveRequired = true
	}
	if netclient.Name == "" {
		logger.Log(0, "setting name")
		netclient.Name, _ = os.Hostname()
		//make sure hostname is suitable
		netclient.Name = config.FormatName(netclient.Name)
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
		port, err := ncutils.GetFreePort(config.DefaultListenPort)
		if err != nil {
			logger.Log(0, "error getting free port", err.Error())
		} else {
			netclient.ListenPort = port
			saveRequired = true
		}
	}
	if netclient.MTU == 0 {
		logger.Log(0, "setting MTU")
		netclient.MTU = config.DefaultMTU
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
	if config.FirewallHasChanged() {
		saveRequired = true
		config.SetFirewall()
	}
	if saveRequired {
		logger.Log(3, "saving netclient configuration")
		if err := config.WriteNetclientConfig(); err != nil {
			logger.FatalLog("could not save netclient config " + err.Error())
		}
	}
	_ = config.ReadServerConf()
	_ = config.ReadNodeConfig()
	if config.CurrServer != "" {
		server := config.GetServer(config.CurrServer)
		if server == nil {
			fail = true
			logger.Log(0, "configuration for", config.CurrServer, "is missing")
		} else {
			if server.MQID != netclient.ID {
				fail = true
				logger.Log(0, server.Name, "is misconfigured: MQID/Password does not match hostid/password")
			}
		}
	}

	if fail {
		logger.FatalLog("configuration is invalid, fix before proceeding")
	}
}
