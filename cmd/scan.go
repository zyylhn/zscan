package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "ms17010,proxyfind,snmp,winscan(smb,netbios,oxid),poc",
}

func init() {
	RootCmd.AddCommand(scanCmd)
}
