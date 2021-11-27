
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version of zscan",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("v1.1.0")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

}
