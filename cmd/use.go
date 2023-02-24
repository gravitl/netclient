package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// useCmd represents the use command
var useCmd = &cobra.Command{
	Use:   "use version",
	Args:  cobra.ExactArgs(1),
	Short: "use a specific version of netclient",
	Long: `use a specific version of netclient if available
For example:- netclient use v0.18.0`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := functions.UseVersion(args[0], true); err != nil {
			fmt.Println("Error using specified version: ", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(useCmd)
}
