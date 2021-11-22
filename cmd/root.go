package cmd

import (
	"github.com/spf13/cobra"
	"time"
)

var Timeout time.Duration
var Thread int
var Hosts string
var Addr string
var Verbose bool
var Output_result bool
var Path_result string
var Log bool
var Username string
var Password string
var Passdict string
var Userdict string
var Command string
var burp bool
var burpthread int
var Hostfile string
var Proxy string

const l1 = "2006-01-02 15:04:05"

var rootCmd = &cobra.Command{
	Use:   "zscan",
	Short: " ______     ______     ______     ______     __   __    \n/\\___  \\   /\\  ___\\   /\\  ___\\   /\\  __ \\   /\\ \"-.\\ \\   \n\\/_/  /__  \\ \\___  \\  \\ \\ \\____  \\ \\  __ \\  \\ \\ \\-.  \\  \n  /\\_____\\  \\/\\_____\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_\\\\\"\\_\\ \n  \\/_____/   \\/_____/   \\/_____/   \\/_/\\/_/   \\/_/ \\/_/ \n",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())

}

func init() {
	rootCmd.PersistentFlags().DurationVarP(&Timeout, "timeout", "t", time.Second*3, "Set `time`out(s) eg:5s")
	rootCmd.PersistentFlags().IntVarP(&Thread, "thread", "T", 100, "Set `thread` eg:2000")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Show verbose information")
	rootCmd.PersistentFlags().BoolVarP(&Output_result, "output", "O", false, "Whether to enter the results into a file（default ./result.txt),can use --path set")
	rootCmd.PersistentFlags().StringVar(&Path_result, "path", "result.txt", "the path of result file")
	rootCmd.PersistentFlags().StringVar(&Proxy, "proxy", "", "Connect with a proxy(user:pass@172.16.95.1:1080 or 172.16.95.1:1080)")
	rootCmd.PersistentFlags().BoolVar(&Log, "log", false, "Record the scan results in chronological order，Save path./log.txt")
}


