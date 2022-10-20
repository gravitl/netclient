/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"strconv"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "display list of netmaker networks",
	Long: `display a list of netmaker networks
long flag provide additional details For example:`,

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
		long, err1 := cmd.Flags().GetBool("long")
		network, err2 := cmd.Flags().GetString("network")
		if err1 != nil || err2 != nil {
			fmt.Println("error getting flags", err1, err2)
		}
		fmt.Println(network, long)
		logger.Log(0, "List called with", network, strconv.FormatBool(long))
		functions.List(network, long)
	},
}

func init() {
	fmt.Println("list init")
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolP("long", "l", false, "display detailed network information")
	listCmd.Flags().StringP("network", "n", "all", "limit display to specified network")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
