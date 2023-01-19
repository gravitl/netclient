package cmd

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy [ on | off ]",
	Short: "proxy on/off",
	Long:  `switches proxy on/off`,
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		status, err := getStatus(args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		err = functions.ChangeProxyStatus(status)
		if err != nil {
			fmt.Println(err.Error())
		}
	},
}

func getStatus(arg string) (status bool, err error) {
	if arg == "on" {
		status = true
	} else if arg == "off" {
		status = false
	} else {
		err = errors.New("invalid argument")
	}
	return
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// uninstallCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// uninstallCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
