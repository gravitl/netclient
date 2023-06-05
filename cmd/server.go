package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// installCmd represents the install command
var setCtx = &cobra.Command{
	Use:   "switch [ servername ]",
	Short: "switch [ servername ]",
	Long:  `sets  netclient to a server config`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := cobra.OnlyValidArgs(cmd, args)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = functions.SwitchServer(args[0])
		if err != nil {
			fmt.Println(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(setCtx)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// installCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// installCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
