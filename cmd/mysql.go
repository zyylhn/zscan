
package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/cobra"
	"net"
	"time"
	"zscan/config"
)

var mysql_port int

// mysqlCmd represents the mysql command
var mysqlCmd = &cobra.Command{
	Use:   "mysql",
	Short: "burp mysql username and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("mysql")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		mysqlmode()
	},
}

func mysqlmode()  {
	burp_mysql()
}

func burp_mysql()  {
	GetHost()
	if Username==""{
		Username=config.Mysqluser
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{mysql_port},Connectmysql,true)
	_=aliveserver.Run()
}

func Connectmysql(ip string, port int) (string, int, error,[]string) {
	conn, err := Getconn(ip,port)
	if conn != nil {
		defer conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("Start burp mysql : ",ip))
		_,f,_:=mysql_auth("zxczxc","zxczxc",ip)
		if f{
			Output(fmt.Sprintf("%v burp success:%v No authentication\n","mysql",ip),LightGreen)
			return ip,port,nil,[]string{"No authentication"}
		}
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,mysql_auth,burpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func mysql_auth(username,password,ip string) (error,bool,string) {
	DSN := fmt.Sprintf("%s:%s@tcp(%s:%v)/?charset=utf8&timeout=%v", username, password, ip,mysql_port,Timeout)
	//注册一个tcp网络，根据是否设置代理返回不同的conn
	mysql.RegisterDialContext("tcp", func(ctx context.Context,network string) (net.Conn, error) {
		return Getconn(network,0)
	})
	db, err := sql.Open("mysql", DSN)
	if err == nil {
		err = db.Ping()
		if err == nil {
			return nil,true,"mysql"
		}
		db.Close()
	}
	return err,false,"mysql"
}


func init() {
	blastCmd.AddCommand(mysqlCmd)
	mysqlCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	mysqlCmd.Flags().StringVarP(&Hosts,"host","H","","Set mysql server host")
	mysqlCmd.Flags().IntVarP(&mysql_port,"port","p",3306,"Set mysql server port")
	mysqlCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	mysqlCmd.Flags().StringVarP(&Username,"username","U","","Set mysql username")
	mysqlCmd.Flags().StringVarP(&Password,"password","P","","Set mysql password")
	mysqlCmd.Flags().StringVarP(&Userdict,"userdict","","","Set mysql userdict path")
	mysqlCmd.Flags().StringVarP(&Passdict,"passdict","","","Set mysql passworddict path")
}
