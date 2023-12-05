package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "The scanning module",
}

func init() {
	RootCmd.AddCommand(scanCmd)
}
