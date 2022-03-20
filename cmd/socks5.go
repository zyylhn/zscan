
package cmd

import (
	"fmt"
	"github.com/armon/go-socks5"
	"github.com/spf13/cobra"
	"os"
)

// socks5Cmd represents the socks5 command
var socks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "Create a socks5 server",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("socks")
	},
	Run: func(cmd *cobra.Command, args []string) {
		Socks5(Addr)
	},
}

func Socks5(addr string)  {
	conf := &socks5.Config{}    //声明一个配置
	if Username==""&&Password!=""{
		Checkerr(fmt.Errorf("You must specify a username\n"))
		os.Exit(0)
	}
	if Username!=""{
		if Password==""{
			Checkerr(fmt.Errorf("You must specify a password\n"))
			os.Exit(0)
		}else {
			userpass:=socks5.StaticCredentials{Username:Password}  //设置用户名密码
			auth:=socks5.UserPassAuthenticator{userpass}
			conf.AuthMethods=[]socks5.Authenticator{auth}   //将认证方式添加到配置里面
		}
	}
	server, err := socks5.New(conf)    //利用配置声明一个server对象
	if err != nil {
		panic(err)
	}
	if err := server.ListenAndServe("tcp", addr); err != nil {    //启动并监听server
		panic(err)
	}
}

func init() {
	serverCmd.AddCommand(socks5Cmd)
	socks5Cmd.Flags().StringVarP(&Addr,"addr","a","0.0.0.0:1080","Specify the IP address and port of the Socks5 service")
	socks5Cmd.Flags().StringVarP(&Username,"username","U","","Set the socks5 service authentication user name")
	socks5Cmd.Flags().StringVarP(&Password,"password","P","","Set the socks5 service authentication password")

}
