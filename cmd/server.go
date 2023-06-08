package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// switchServer command is used to set netclient context to a server, it has registered already.
var switchServer = &cobra.Command{
	Use:   "switch [ servername ]",
	Short: "switch [ servername ]",
	Long:  `switches netclient to a registered server`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := functions.SwitchServer(args[0])
		if err != nil {
			fmt.Println(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(switchServer)
}
