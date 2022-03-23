
package cmd

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
	"net"
	"time"
)


var redis_port int
// redisCmd represents the redis command
var redisCmd = &cobra.Command{
	Use:   "redis",
	Short: "burp redis password",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("redis")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		Redis()
	},
}

func Redis()  {
	burp_redis()
}

func burp_redis()  {
	GetHost()
	ips := Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{redis_port},Connectredis,true)
	_=aliveserver.Run()
}

func Connectredis(ip string, port int) (string, int, error,[]string) {
	conn, err := Getconn(ip,port)
	defer func() {
		if conn != nil {
			_ = conn.Close()
			fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
			fmt.Println(Yellow("\rStart burp redis : ",ip))
			_,f,_:=redis_auth("","",ip)
			if f{
				Output(fmt.Sprintf("%v:\tNo authentication\n",ip),LightGreen)
				return
			}
			startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,redis_auth,burpthread)
			startburp.Run()
		}
	}()
	return ip, port, err,nil
}


//获取redis连接的函数
func redis_client(user,pass,ip string) (*redis.Client) {
	url:=fmt.Sprintf("redis://%v:%v@%v:%v/",user,pass,ip,redis_port)
	opt,err:=redis.ParseURL(url)
	if err != nil {
		return nil
	}
	dialer:= func(ctx context.Context,network,addr string)(net.Conn,error) {
		return Getconn(addr,0)
	}
	opt.Dialer=dialer
	return redis.NewClient(opt)
}

//burp功能的身份认证函数
func redis_auth(user,pass,ip string) (error,bool,string) {
	rbd:=redis_client(user,pass,ip)
	if rbd==nil{
		return fmt.Errorf(""),false,"redis"
	}
	_,err:=rbd.Ping(context.Background()).Result()
	if err!=nil{
		return err,false,"redis"
	}
	return nil,true,"redis"
}

func init() {
	blastCmd.AddCommand(redisCmd)
	redisCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	redisCmd.Flags().StringVarP(&Hosts,"host","H","","Set redis server host")
	redisCmd.Flags().IntVarP(&redis_port,"port","p",6379,"Set redis server port")
	redisCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	redisCmd.Flags().StringVarP(&Command,"command","c","","Set the command you want to execute")
	redisCmd.Flags().StringVarP(&Password,"password","P","","Set redis password")
	redisCmd.Flags().StringVarP(&Passdict,"passdict","","","Set redis passworddict path")
}
