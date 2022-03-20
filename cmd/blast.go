package cmd

import (
	"github.com/spf13/cobra"
)

// blastCmd represents the blast command
var blastCmd = &cobra.Command{
	Use:   "blast",
	Short: "Common service blasting",
}

func init() {
	RootCmd.AddCommand(blastCmd)
}
