// Package cmd command line for netclient
/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
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
	cobra.OnInitialize(initConfig, functions.Migrate)
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
	config.InitConfig(flags)
	setupLogging(flags)
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

func setupLogging(flags *viper.Viper) {
	logLevel := &slog.LevelVar{}
	replace := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.SourceKey {
			a.Value = slog.StringValue(filepath.Base(a.Value.String()))
		}
		return a
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, ReplaceAttr: replace, Level: logLevel}))
	slog.SetDefault(logger)
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
