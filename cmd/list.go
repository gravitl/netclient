/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list [network]",
	Args:  cobra.RangeArgs(0, 1),
	Short: "display list of netmaker networks",
	Long: `display details of netmaker networks
long flag provide additional details For example:
netclient list mynet    //display details of mynet network
netclient list mynet -l //display extended details of mynet network
netclient list          //display details of all networks
netclient list  -l      //display extented details of all networks
`,

	Run: func(cmd *cobra.Command, args []string) {
		long, err := cmd.Flags().GetBool("long")
		if err != nil {
			logger.Log(0, "error getting flags", err.Error())
		}
		if len(args) > 0 {
			functions.List(args[0], long)
		} else {
			functions.List("", long)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolP("long", "l", false, "display detailed network information")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
