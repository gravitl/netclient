package cmd

import (
	"fmt"
	"runtime"
	"strings"

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
		if args[0] == "netmaker-test" || args[0] == "utun70" {
			fmt.Println("cannot use `netmaker-test` interface")
			return
		}
		if runtime.GOOS == "darwin" && !strings.HasPrefix(args[0], "utun") {
			fmt.Println("use utun as interface on darwin")
			return
		}
		if runtime.GOOS != "darwin" && !strings.HasPrefix(args[0], "netmaker") {
			fmt.Println("invalid interface name, should contain `netmaker` as prefix")
			return
		}
		config.Netclient().Interface = args[0]
		if err := config.WriteNetclientConfig(); err != nil {
			fmt.Println("failed to save netclient config")
			return
		}
		restart, err := cmd.Flags().GetBool("restart-daemon")
		if err != nil {
			fmt.Println("failed to set interface ", err)
			return
		}
		err = functions.Push(restart)
		if err != nil {
			fmt.Println("failed to push data to server", err.Error())
		}

	},
}

func init() {
	rootCmd.AddCommand(interfaceCmd)
	interfaceCmd.Flags().BoolP("restart-daemon", "D", true, "when set to true, daemon will be restarted")
}
