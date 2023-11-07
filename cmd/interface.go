package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/ncutils"
	"github.com/spf13/cobra"
)

// interfaceCmd represents the interface command
var interfaceCmd = &cobra.Command{
	Use:   "interface",
	Args:  cobra.ExactArgs(1),
	Short: "sets netclient interface name",
	Long:  `used to set interface name`,
	Run: func(cmd *cobra.Command, args []string) {
		exists, err := ncutils.InterfaceExists(args[0])
		if err != nil {
			fmt.Println("error checking for interfaces ", err)
			return
		}
		if exists {
			fmt.Printf("iface `%s` already exists\n", args[0])
			return
		}
		if args[0] == "netmaker-test" {
			fmt.Println("cannot use `netmaker-test`")
			return
		}
		config.Netclient().Interface = args[0]
		err = functions.Push(false)
		if err != nil {
			fmt.Println("failed to push data to server", err.Error())
		}

	},
}

func init() {
	rootCmd.AddCommand(interfaceCmd)
}
