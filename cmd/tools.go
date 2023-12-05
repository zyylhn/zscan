package cmd

import (
	"github.com/spf13/cobra"
)

// toolsCmd represents the tools command
var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Commonly used tools",
}

func init() {
	RootCmd.AddCommand(toolsCmd)
}
