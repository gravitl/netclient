/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

var (
	onpremInstall bool
)

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "install netclient binary and daemon",
	Long: `install netclient binary and daemon. For example:

./netclient install [command options] [arguments]

ensure you specify the full path to then new binary to be installed`,
	Run: func(cmd *cobra.Command, args []string) {
		functions.Install(onpremInstall)
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().BoolVarP(&onpremInstall, "onprem", "", false, "set if using on-prem server")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// installCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// installCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
