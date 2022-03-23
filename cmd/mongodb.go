package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/mgo.v2"
	"net"
	"time"
)

var mongodb_port int

var mongodbCmd = &cobra.Command{
	Use:   "mongo",
	Short: "burp mongodb username and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("mongodb")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		mongodb()
	},
}

func mongodb()  {
	burp_mongodb()
}

func burp_mongodb()  {
	GetHost()
	if Command!=""{
		err,_,_:=mongodb_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="amdin,mongodb"
	}
	ips:= Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{mongodb_port},Connectmongodb,true)
	_=aliveserver.Run()
}

func Connectmongodb(ip string, port int) (string, int, error,[]string) {
	conn, err := Getconn(ip, port)
	defer func() {
		if conn != nil {
			_ = conn.Close()
			fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
			fmt.Println(Yellow("Start burp mongodb : ",ip))
			_,f,_:=mongodb_auth("","",ip)
			if f{
				Output(fmt.Sprintf("%v:\tNo authentication\n",ip),LightGreen)
				return
			}
			startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,mongodb_auth,burpthread)
			startburp.Run()
		}
	}()
	return ip, port, err,nil
}

func mongodb_auth(username,password,ip string) (error,bool,string) {

	dialInfo := &mgo.DialInfo{
		DialServer: func(addr *mgo.ServerAddr) (net.Conn, error) {
			return Getconn(ip, mongodb_port)
		},
		Addrs:     []string{fmt.Sprintf("%s:%d", ip, mongodb_port)},
		Direct:    false,
		Timeout:   Timeout,
		Database:  "test",
		Source:    "admin",
		Username:  username,
		Password:  password,
		PoolLimit: 4096,
	}

	db, err := mgo.DialWithInfo(dialInfo)

	if err == nil {
		err = db.Ping()
		if err == nil {
			return nil,true,"mongodb"
		}
		db.Close()
	}
	return err,false,"mongdb"
}


func init() {
	blastCmd.AddCommand(mongodbCmd)
	mongodbCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	mongodbCmd.Flags().StringVarP(&Hosts,"host","H","","Set mongodb server host")
	mongodbCmd.Flags().IntVarP(&mongodb_port,"port","p",27017,"Set mongodb server port")
	mongodbCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	mongodbCmd.Flags().StringVarP(&Username,"username","U","","Set mongodb username")
	mongodbCmd.Flags().StringVarP(&Password,"password","P","","Set mongodb password")
	mongodbCmd.Flags().StringVarP(&Userdict,"userdict","","","Set mongodb userdict path")
	mongodbCmd.Flags().StringVarP(&Passdict,"passdict","","","Set mongodb passworddict path")
	//mongodbCmd.MarkFlagRequired("host")

}
