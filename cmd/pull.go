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
	Long:  `get the latest host configuration and peers from all connected servers`,
	Run: func(cmd *cobra.Command, args []string) {
		_, err := functions.Pull(true)
		if err != nil {
			logger.Log(0, "failed to pull", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(pullCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pullCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pullCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
