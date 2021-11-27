package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"net"
	"os"
	"sync"
)

var listen bool

// ncCmd represents the nc command
var ncCmd = &cobra.Command{
	Use:   "nc",
	Short: "A easy nc",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("nc")
	},
	Run: func(cmd *cobra.Command, args []string) {
		if listen {
			Listen(Addr)
		} else {
			Dial(Addr)
		}
	},
}

//监听端口等待连接
func Listen(ladd string) {
	var wg sync.WaitGroup
	wg.Add(2)
	tcpip, err := net.ResolveTCPAddr("tcp", ladd)
	Checkerr(err)
	tcplisten, err := net.ListenTCP("tcp", tcpip)
	defer tcplisten.Close()
	Checkerr(err)
	fmt.Println(Yellow("Waiting for connection"))
	for {
		c, err := tcplisten.AcceptTCP()
		Checkerr(err)
		fmt.Println(Yellow("Success connect from " + c.RemoteAddr().String()))
		go output(&wg, c)
		go getin(&wg, c)
		wg.Wait()
		c.Close()
	}
}

//主动连接目标
func Dial(radd string) {
	var wg sync.WaitGroup
	wg.Add(2)
	tcpadd, err := net.ResolveTCPAddr("tcp", radd)
	Checkerr(err)
	c, err := net.DialTCP("tcp", nil, tcpadd)
	if err != nil {
		Checkerr(err)
		os.Exit(0)
	}
	fmt.Println(LightGreen("Success connect to " + radd))
	go output(&wg, c)
	go getin(&wg, c)
	wg.Wait()
	c.Close()
}

//从conn中读取数据
func output(wg *sync.WaitGroup, c *net.TCPConn) {
	defer wg.Done()
	buf := make([]byte, 1024)
	for {
		n, err := c.Read(buf)
		if err == io.EOF {
			os.Exit(0)
		}
		os.Stdout.Write(buf[:n])
	}
}

//从终端获取数据到Conn
func getin(wg *sync.WaitGroup, c *net.TCPConn) {
	defer wg.Done()
	c.ReadFrom(os.Stdin)
}

func init() {
	rootCmd.AddCommand(ncCmd)
	ncCmd.Flags().StringVarP(&Addr, "addr", "a", "", "listen/connect host address eg(listen):-a 0.0.0.0:4444  eg(connect):-a 172.16.95.1:4444")
	ncCmd.Flags().BoolVarP(&listen, "listen", "l", false, "listen mode(default connect)")
	ncCmd.MarkFlagRequired("addr")
}
