/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list [network | all]",
	Args:  cobra.ExactArgs(1),
	Short: "display list of netmaker networks",
	Long: `display details of netmaker networks
long flag provide additional details For example:
netclient list mynet
netclient list mynet -l
netclient list all
netclient list all -l
`,

	Run: func(cmd *cobra.Command, args []string) {
		long, err := cmd.Flags().GetBool("long")
		if err != nil {
			logger.Log(0, "error getting flags", err.Error())
		}
		functions.List(args[0], long)
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
