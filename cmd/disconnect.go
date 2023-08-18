/*
Copyright © 2022 Netmaker Team info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// disconnectCmd represents the disconnect command
var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "disconnet from a network",
	Long: `disconnect from the specified network
For example:

netclient disconnect my-network-name`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("\nPlease specify the network name as the argument. For example: netclient disconnect my-network-name")
			nodes := config.GetNodes()
			if len(nodes) > 0 {
				fmt.Println("\nAvailable Networks:")
				for _, node := range nodes {
					fmt.Println(node.Network)
				}
			} else {
				fmt.Println("\nNo Networks Available")
			}
		} else {
			fmt.Println("disconnect called", args)
			if err := functions.Disconnect(args[0]); err != nil {
				fmt.Println("\nnode disconnect failed: ", err)
			} else {
				fmt.Println("\nnode is disconnected from", args[0])
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(disconnectCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// disconnectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// disconnectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
