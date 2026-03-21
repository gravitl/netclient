/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/ncutils"
	"github.com/spf13/cobra"
)

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "install netclient binary and daemon",
	Long: `install netclient binary and daemon. For example:

./netclient install [command options] [arguments]

ensure you specify the full path to then new binary to be installed`,
	Run: func(cmd *cobra.Command, args []string) {
		setInterfaceFields(cmd)
		functions.Install()
	},
}

func setInterfaceFields(cmd *cobra.Command) {
	port, err := cmd.Flags().GetInt(registerFlags.Port)
	if err == nil && port != 0 && port != config.Netclient().ListenPort {
		// check if port is available
		if !ncutils.IsPortFree(port) {
			fmt.Printf("port %d is not free\n", port)
			os.Exit(1)
		}
		config.Netclient().ListenPort = port
		config.Netclient().IsStaticPort = true
	}

	if ifaceName, err := cmd.Flags().GetString(registerFlags.Interface); err == nil && ifaceName != "" {
		if !validateIface(ifaceName) {
			fmt.Println("invalid interface name", ifaceName)
			os.Exit(1)
		}
		config.Netclient().Interface = ifaceName
	}

	if fwmark, err := cmd.Flags().GetInt(registerFlags.FwMark); err == nil && fwmark != 0 {
		config.Netclient().FwMark = fwmark
	}
}

func init() {
	installCmd.Flags().IntP(registerFlags.Port, "p", 0, "sets wg listen port")
	installCmd.Flags().StringP(registerFlags.Interface, "I", "", "sets netmaker interface to use on host")
	installCmd.Flags().IntP(registerFlags.FwMark, "F", 0, "sets firewall mark for netmaker traffic")
	rootCmd.AddCommand(installCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// installCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// installCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
