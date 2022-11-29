// Package cmd command line for netclient
/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"crypto/rand"
	"os"
	"runtime"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
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
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().IntP("verbosity", "v", 0, "set loggin verbosity 0-4")
	viper.BindPFlags(rootCmd.Flags())

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	checkUID()
	viper.AddConfigPath(config.GetNetclientPath())
	viper.SetConfigName("netclient.yml")
	viper.SetConfigType("yml")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.AutomaticEnv() // read in environment variables that match
	//not sure why vebosity not set in AutomaticEnv
	viper.BindEnv("verbosity", "VERBOSITY")

	// If a config file is found, read it in
	if err := config.Lock(config.ConfigLockfile); err != nil {
		logger.Log(0, "failed to obtain lockfile", err.Error())
	}
	if err := viper.ReadInConfig(); err == nil {
		logger.Log(0, "Using config file:", viper.ConfigFileUsed())
	} else {
		logger.Log(0, "error reading config file", err.Error())
	}
	if err := config.Unlock(config.ConfigLockfile); err != nil {
		logger.Log(0, "failed to releas lockfile", err.Error())
	}
	var netclient config.Config
	//viper cannot unmarshal net.IPNet so need to do a funky conversion
	//if err := viper.Unmarshal(&netclient); err != nil {
	//logger.Log(0, "could not read netclient config file", err.Error())
	//}
	c := viper.AllSettings()
	b, _ := yaml.Marshal(c)
	if err := yaml.Unmarshal(b, &netclient); err != nil {
		logger.Log(0, "could not read netclient config file", err.Error())
	}

	logger.Verbosity = netclient.Verbosity
	config.UpdateNetclient(netclient)
	config.ReadNodeConfig()
	config.ReadServerConf()
	checkConfig()
	//check netclient dirs exist
	if _, err := os.Stat(config.GetNetclientPath()); err != nil {
		if os.IsNotExist(err) {
			if err := os.Mkdir(config.GetNetclientPath(), os.ModePerm); err != nil {
				logger.Log(0, "failed to create dirs", err.Error())
			}
		} else {
			logger.FatalLog("could not create /etc/netclient dir" + err.Error())
		}
	}
	wireguard.WriteWgConfig(config.Netclient(), config.GetNodes())
}

func checkConfig() {
	fail := false
	saveRequired := false
	netclient := config.Netclient()
	if netclient.OS != runtime.GOOS {
		logger.Log(0, "setting OS")
		netclient.OS = runtime.GOOS
		saveRequired = true
	}
	if netclient.Version != config.Version {
		logger.Log(0, "setting version")
		netclient.Version = config.Version
		saveRequired = true
	}
	netclient.IPForwarding = true
	if netclient.HostID == "" {
		logger.Log(0, "setting netclient hostid")
		netclient.HostID = uuid.NewString()
		netclient.HostPass = ncutils.MakeRandomString(32)
		saveRequired = true
	}
	if netclient.Name == "" {
		logger.Log(0, "setting name")
		netclient.Name, _ = os.Hostname()
		saveRequired = true
	}
	if netclient.Interface == "" {
		logger.Log(0, "setting interface name")
		netclient.Interface = "netmaker"
		saveRequired = true
	}
	if netclient.MacAddress == nil {
		logger.Log(0, "setting macAddress")
		mac, err := ncutils.GetMacAddr()
		if err != nil {
			logger.FatalLog("failed to set macaddress", err.Error())
		}
		netclient.MacAddress = mac[0]
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
	if netclient.FirewallInUse == "" {
		saveRequired = true
		if ncutils.IsLinux() {
			if ncutils.IsNFTablesPresent() {
				netclient.FirewallInUse = models.FIREWALL_NFTABLES
			} else {
				netclient.FirewallInUse = models.FIREWALL_IPTABLES
			}
		} else {
			// defaults to iptables for now, may need another default for non-Linux OSes
			netclient.FirewallInUse = models.FIREWALL_IPTABLES
		}
	}

	if saveRequired {
		logger.Log(3, "saving netclient configuration")
		if err := config.WriteNetclientConfig(); err != nil {
			logger.FatalLog("could not save netclient config " + err.Error())
		}
	}
	config.ReadServerConf()
	for _, server := range config.Servers {
		if server.MQID != netclient.HostID || server.Password != netclient.HostPass {
			fail = true
			logger.Log(0, server.Name, "is misconfigured: MQID/Password does not match hostid/password")
		}
	}
	config.ReadNodeConfig()
	nodes := config.GetNodes()
	for _, node := range nodes {
		//make sure server config exists
		server := config.GetServer(node.Server)
		if server == nil {
			fail = true
			logger.Log(0, "configuration for", node.Server, "is missing")
		}
	}
	if fail {
		logger.FatalLog("configuration is invalid, fix before proceeding")
	}
}
