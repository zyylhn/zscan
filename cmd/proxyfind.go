package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"time"
)

var proxy_type string
var proxy_port string

var SocksServerScanCmd = &cobra.Command{
	Use:   "proxyfind",
	Short: "Scan proxy",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("SocksScan")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		proxyfind()
	},
}

func proxyfind()  {
	GetHost()
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	ports, err := Parse_Port(proxy_port)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,ports,Connect_SocksScan,true)
	r:=aliveserver.Run()
	PrintResult_Socks(r)
}

func Connect_SocksScan(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn(ip,port)
	if conn!=nil{
		result:=""
		switch proxy_type {
		case "socks5":
			b,s:=Socks5Find(conn)
			if b {
				result=result+s
				return ip,port,nil,[]string{result}
			}
		case "socks4":
			b,s:=Socks4Find(conn)
			if b {
				result=result+s
				return ip,port,nil,[]string{result}
			}
		default:
			fmt.Println(Red(fmt.Sprintf("Does not support %v",proxy_type)))
		}
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	err=fmt.Errorf("")
	return ip, port, err,nil
}

func Socks5Find(conn net.Conn) (bool,string) {
	conn.Write([]byte{0x05,0x03,0x00,0x01,0x02})
	buf:=make([]byte,128)
	conn.SetReadDeadline((time.Now().Add(Timeout)))
	n,_:=conn.Read(buf)
	if n==2&&buf[0]==0x05 {
		s := "Find Socks5 Server"
		switch buf[1] {
		case 0x00:
			s = s + "\tNo authentication required"
		case 0x02:
			s = s + "\tUsername and password authentication"
		default:
			s=fmt.Sprintf("%s\tDon't know aunthentication\t%x",s,buf[1])
		}
		return true, s
	}
	return false,""
}
func Socks4Find(conn net.Conn) (bool,string) {
	conn.Write([]byte{0x04,0x01,0x01,0x01,0x7f,0x00,0x00,0x01,0x00,0x00})
	buf:=make([]byte,128)
	conn.SetReadDeadline((time.Now().Add(Timeout)))
	n,_:=conn.Read(buf)
	if n==8&&buf[0]==0x00{
		s:="Find Socks4 Server"
		switch buf[1] {
		case 0x5a:
			s=s+"\tAllow the request"
		default:
			s=s+"\tRequest error"
		}
		return true,s
	}
	return false,""

}


func PrintResult_Socks(r map[string]*Openport)  {
	Output("\n\r===========================port result list=============================\n",LightGreen)
	for _,i:=range r{
		Output(fmt.Sprintf("Traget:%v\n",i.ip),LightBlue)
		for _,p:=range i.port{
			Output(fmt.Sprintf("%v\t%v\n",p,i.banner[p][0]),White)
		}
	}
}


func init() {
	rootCmd.AddCommand(SocksServerScanCmd)
	SocksServerScanCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	SocksServerScanCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap) eg:192.168.1.1/24,172.16.95.1-100,127.0.0.1")
	SocksServerScanCmd.Flags().StringVarP(&proxy_port, "ports", "p", "1080,1089,8080,7890,10808", "Set `port` eg:1-1000,3306,3389")
	SocksServerScanCmd.Flags().StringVar(&proxy_type, "type", "socks5", "Set the scan proxy type(socks4/socks5/http)")
	//SocksServerScanCmd.MarkFlagRequired("host")
	//SocksServerScanCmd.MarkFlagRequired("ports")
}
