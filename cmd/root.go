package cmd

import (
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
	"sync"
	"time"
)

var Timeout time.Duration
var Thread int
var Hosts string
var Addr string
var Verbose bool
var Path_result string
var Username string
var Password string
var Passdict string
var Userdict string
var Command string
//var burp bool
var burpthread int
var Hostfile string
var Proxy string
var proxyconn proxy.Dialer
var No_progress_bar bool
var OutputChan chan string
var stopchan chan int
var psresultlock sync.RWMutex
var runmod bool

const l1 = "2006-01-02 15:04:05"

var RootCmd = &cobra.Command{
	Use:   "zscan",
	Short: " ______     ______     ______     ______     __   __    \n/\\___  \\   /\\  ___\\   /\\  ___\\   /\\  __ \\   /\\ \"-.\\ \\   \n\\/_/  /__  \\ \\___  \\  \\ \\ \\____  \\ \\  __ \\  \\ \\ \\-.  \\  \n  /\\_____\\  \\/\\_____\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_\\\\\"\\_\\ \n  \\/_____/   \\/_____/   \\/_____/   \\/_/\\/_/   \\/_/ \\/_/ \n",
}

func Execute() {
	runmod=false
	stopchan=make(chan int)
	cobra.CheckErr(RootCmd.Execute())
	if runmod{
		<-stopchan
	}
}

func init() {
	RootCmd.PersistentFlags().DurationVarP(&Timeout, "timeout", "t", time.Second*5, "Set `time`out(s) eg:5s")
	RootCmd.PersistentFlags().IntVarP(&Thread, "thread", "T", 600, "Set `thread` eg:2000")
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Show verbose information")
	RootCmd.PersistentFlags().StringVarP(&Path_result, "output","o", "result.txt", "the path of result file")
	RootCmd.PersistentFlags().StringVar(&Proxy, "proxy", "", "Connect with a proxy(user:pass@172.16.95.1:1080 or 172.16.95.1:1080)")
	RootCmd.PersistentFlags().BoolVar(&No_progress_bar, "nobar", false, "disable portscan progress bar")
}


