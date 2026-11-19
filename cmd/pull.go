/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// pullCmd represents the pull command
var pullCmd = &cobra.Command{
	Use:   "pull",
	Args:  cobra.ExactArgs(0),
	Short: "get the latest host configuration",
	Long:  `get the latest host configuration and peers from the connected server`,
	Run: func(cmd *cobra.Command, args []string) {
		resetConnections, _ := cmd.Flags().GetBool("reset-connections")
		_, _, _, err := functions.Pull(true, resetConnections, false)
		if err != nil {
			logger.Log(0, "failed to pull", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(pullCmd)
	pullCmd.Flags().Bool("reset-connections", false,
		"reset auto-relay peer connections on the server (default: keep existing)")
}
