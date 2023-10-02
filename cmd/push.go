package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// pushCmd represents the `netclient push` command
var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "push host config to server",
	Long:  `updates host config locally and updates server`,
	Run: func(cmd *cobra.Command, args []string) {
		setHostFields(cmd)
		err := functions.Push()
		if err != nil {
			logger.Log(0, "failed to push", err.Error())
		}
	},
}

func init() {
	pushCmd.Flags().StringP(registerFlags.EndpointIP, "e", "", "sets endpoint on host")
	pushCmd.Flags().IntP(registerFlags.Port, "p", 0, "sets wg listen port")
	pushCmd.Flags().IntP(registerFlags.MTU, "m", 0, "sets MTU on host")
	pushCmd.Flags().BoolP(registerFlags.Static, "i", false, "flag to set host as static")
	pushCmd.Flags().StringP(registerFlags.Name, "o", "", "sets host name")
	rootCmd.AddCommand(pushCmd)
}
