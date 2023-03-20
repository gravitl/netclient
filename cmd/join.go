/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// joinCmd represents the join command
var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "join a network",
	Long: `join a netmaker network using: 

token: netclient join -t <token> // join using token`,
	Run: func(cmd *cobra.Command, args []string) {
		token, err := cmd.Flags().GetString("token")
		if err != nil {
			cmd.Usage()
			return
		}
		err = functions.Register(token)
		if err != nil {
			logger.Log(0, "join failed", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(joinCmd)
	joinCmd.Flags().StringP("token", "t", "", "enrollment token for joining network")
}
