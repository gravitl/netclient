/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"errors"
	"runtime"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "install netclient binary and daemon",
	Long: `install netclient binary and daemon. For example:

./netclient install [command options] [arguments]

ensure you specify the full path to then new binary to be installed`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS == "windows" {
			cmd.SilenceUsage = true
			return errors.New("cmd install on Windows is deprecated, please install with msi installer")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		functions.Install()
	},
}

func init() {
	rootCmd.AddCommand(installCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// installCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// installCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
