/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// guiServerCmd enables or disables the gui http server
var guiServerCmd = &cobra.Command{
	Use:       "guiServer [enable|disable]",
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Short:     "guiServer [enable|disable]",
	ValidArgs: []string{"enable", "disable"},
	Long:      `enable or disable the gui http server`,

	Run: func(cmd *cobra.Command, args []string) {
		enableServer(args[0])
	},
}

func init() {
	rootCmd.AddCommand(guiServerCmd)
}

func enableServer(cmd string) {
	disable := false
	if cmd == "disable" {
		disable = true
	}
	if disable != config.Netclient().DisableGUIServer {
		config.Netclient().DisableGUIServer = disable
		config.WriteNetclientConfig()
		logger.Log(0, "restarting netclient daemon")
		daemon.Stop()
		daemon.Start()
		return
	}
	logger.Log(0, "no change ... exiting")
}
