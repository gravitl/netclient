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
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if functions.IsDesktopBuild() {
			cmd.SilenceUsage = true
			return fmt.Errorf("desktop builds do not self-update; use the Netmaker Desktop app/installer (version: %s)", args[0])
		}
		return refuseIfDesktopSession(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		skip, err := functions.UseVersion(args[0], true)
		if skip {
			if functions.IsContainerized() {
				fmt.Printf("skipping use version inside container, update the container image instead (version: %s)\n", args[0])
			} else if functions.IsDesktopBuild() {
				fmt.Printf("skipping use version on desktop build; Desktop manages updates (version: %s)\n", args[0])
			} else {
				fmt.Printf("skipping use version (version: %s)\n", args[0])
			}
		} else if err != nil {
			fmt.Println("Error using specified version: ", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(useCmd)
}
