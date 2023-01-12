/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "connect",
	Args:  cobra.ExactArgs(1),
	Short: "connect to a netmaker network",
	Long: `connect to specified network
For example:

netclient connect my-network`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := functions.Connect(args[0]); err != nil {
			fmt.Println("\nconnect failed:", err)
		} else {
			fmt.Println("\nnode is connected to", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// connectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// connectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
