/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// leaveCmd represents the leave command
var leaveCmd = &cobra.Command{
	Use:   "leave <network>",
	Args:  cobra.ExactArgs(1),
	Short: "leave a network",
	Long: `leave the specified network 
For example:

netclient leave my-network`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Log(0, "leave called")
		faults, err := functions.LeaveNetwork(args[0], false)
		if err != nil {
			fmt.Println(err.Error())
			for _, fault := range faults {
				fmt.Println(fault.Error())
			}
		} else {
			fmt.Println("successfully left network ", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(leaveCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// leaveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// leaveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
