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

// listCmd represents the list command
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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
		//time.Sleep(time.Second * 5)
		daemon.Start()
		return
	}
	logger.Log(0, "no change ... exiting")
}
