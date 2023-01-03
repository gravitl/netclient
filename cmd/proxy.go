package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// proxyCmd represents the netclient proxy command
var proxyCmd = &cobra.Command{
	Use:   "use version",
	Args:  cobra.ExactArgs(1),
	Short: "enable/disable proxy for netclient",
	Long: `enable/disable proxy for netclient
For example:- netclient proxy true`,
	Run: func(cmd *cobra.Command, args []string) {
		status := args[0] == "true"
		functions.Proxy(status)
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
}
