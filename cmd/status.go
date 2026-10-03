package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "show current network status",
	Long: `Show the current host, interface, and joined networks.

Use --wg to print the live WireGuard interface in the same form as "wg show".

Examples:
  netclient status
  netclient status --wg`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		wg, err := cmd.Flags().GetBool("wg")
		if err != nil {
			return err
		}
		return functions.ShowStatus(wg)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().Bool("wg", false, "print WireGuard output in the same form as wg show")
}
