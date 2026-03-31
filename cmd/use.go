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
		skip, err := functions.UseVersion(args[0], true)
		if skip {
			fmt.Println("skipping auto-upgrade inside container, update the container image instead", "version", args[0])
		}
		if err != nil {
			fmt.Println("Error using specified version: ", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(useCmd)
}
