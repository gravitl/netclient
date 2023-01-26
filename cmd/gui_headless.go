//go:build headless
// +build headless

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// guiCmd represents the gui command
var guiCmd = &cobra.Command{
	Use:   "gui",
	Args:  cobra.ExactArgs(0),
	Short: "start the netclient GUI",
	Long: `utilize the netclient Graphical User Interface (aka. GUI)
For example:

netclient gui`,
	Run: func(cmd *cobra.Command, args []string) {
		gui()
	},
}

func init() {
	rootCmd.AddCommand(guiCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// connectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// connectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
func gui() {
	fmt.Println("I regret to inform you, this netclient is headless")
}
