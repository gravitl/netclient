/*
Copyright © 2023 Netmaker Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "server commands [list, switch, leave]",
	Long:  `list, switch or leave server`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("server called")
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.AddCommand(leaveServerCmd)
	serverCmd.AddCommand(listServersCmd)
	serverCmd.AddCommand(switchServerCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// leaveServerCmd represents the serverleave command
var leaveServerCmd = &cobra.Command{
	Use:   "leave [servername]",
	Short: "leave a server",
	Long:  `leave the specified server`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := functions.LeaveServer(args[0]); err != nil {
			fmt.Println(err.Error())
		}
	},
}

// listServersCmd represents the serverlist command
var listServersCmd = &cobra.Command{
	Use:   "list",
	Short: "list servers",
	Long:  `list connected servers`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := functions.ListServers(); err != nil {
			fmt.Println(err.Error())
		}
	},
}

// switchServerCmd represents the serverswitch command
var switchServerCmd = &cobra.Command{
	Use:   "switch [servername]",
	Short: "switch to a server",
	Long:  `switch to the named server`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := functions.SwitchServer(args[0]); err != nil {
			fmt.Println(err.Error())
		}
	},
}
