package cmd

import (
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "start http server or socks5 server",
}

func init() {
	RootCmd.AddCommand(serverCmd)
}
