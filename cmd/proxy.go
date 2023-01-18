package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy [ on | off ]",
	Short: "proxy on/off",
	Long:  `switches proxy on/off`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("\nmissing status [ on | off ] argument in the command")
			return
		}
		err := functions.ChangeProxyStatus(getStatus(args[0]))
		if err != nil {
			fmt.Println(err.Error())
		}
	},
}

func getStatus(status string) bool {
	return status == "on"
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
