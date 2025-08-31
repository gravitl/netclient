/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

var (
	onpremDaemon bool
)

// daemonCmd represents the daemon command
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "nodeshift daemon",
	Long:  `nodeshift daemon gets and sends updates to netmaker server"`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("daemon called")
		functions.Daemon(onpremDaemon)
	},
}

func init() {
	rootCmd.AddCommand(daemonCmd)
	daemonCmd.Flags().BoolVarP(&onpremDaemon, "onprem", "", false, "set if using on-prem server")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// daemonCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// daemonCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
