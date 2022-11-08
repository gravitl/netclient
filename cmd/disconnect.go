/*
Copyright © 2022 Netmaker Team info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// disconnectCmd represents the disconnect command
var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Args:  cobra.ExactArgs(1),
	Short: "disconnet from a network",
	Long: `disconnect from the specified network
For example:

netclient disconnect my-network`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("disconnect called", args)
		functions.Disconnect(args[0])
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
