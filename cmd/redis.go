
package cmd

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
	"net"
	"strings"
	"time"
)


var redis_port int
// redisCmd represents the redis command
var redisCmd = &cobra.Command{
	Use:   "redis",
	Short: "burp redis password",
	PreRun: func(cmd *cobra.Command, args []string) {
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
	switch  {
	case Command!="":
		if err,f,_:=redis_auth("",Password,Hosts);f{
			redis_exec(Command,redis_client(Username,Password,Hosts))
		}else {fmt.Println(Red(err))}
	default:
		//iplist,err:=Parse_IP(Hosts)
		//Checkerr_exit(err)
		burp_redis()
	}
}

func burp_redis()  {
	GetHost()
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
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
	Output(getinfomation(rbd),LightCyan)
	return nil,true,"redis"
}

//命令执行模块的执行函数
func redis_exec(cmd string,client *redis.Client)  {
	ctx:=context.Background()
	args:=strings.Fields(cmd)
	switch len(args) {
	case 1:
		val, err := client.Do(ctx, args[0]).Result()
		redis_checkerr(val, err)
	case 2:
		val, err := client.Do(ctx, args[0], args[1]).Result()
		redis_checkerr(val, err)
	case 3:
		val, err := client.Do(ctx, args[0], args[1], args[2]).Result()
		redis_checkerr(val, err)
	case 4:
		val, err := client.Do(ctx, args[0], args[1], args[2], args[3]).Result()
		redis_checkerr(val, err)
	case 5:
		val, err := client.Do(ctx, args[0], args[1], args[2], args[3], args[4]).Result()
		redis_checkerr(val, err)
	default:
		fmt.Println(Yellow("Too many args"))
	}
}

//命令执行模块的检查和输出函数
func redis_checkerr(val interface{},err error)  {
	if err != nil {
		if err == redis.Nil {
			fmt.Println(Red("Key does not exits"))
			return
		}
		fmt.Println(Yellow(err))
	}
	switch v:=val.(type){
	case string:
		fmt.Println(v)
	case []string:
		fmt.Println(strings.Join(v," "))
	default:
		fmt.Println(v)
	}
}

//获取redis基本信息
func getinfomation(client *redis.Client) string {
	var redis_version string
	var os string
	var arch string
	var executable string
	var configfile string

	val,err:=client.Do(context.Background(),"info").Result()
	Checkerr(err)
	info:=val.(string)
	info_list:=strings.Split(info,"\r\n")
	info_list=info_list[0:23]
	for _,v:=range info_list{
		switch  {
		case strings.Contains(v,"redis_version:"):
			redis_version=v
		case strings.Contains(v,"os:"):
			os=v
		case strings.Contains(v,"arch_bits:"):
			arch=v
		case strings.Contains(v,"executable:"):
			executable=v
		case strings.Contains(v,"config_file:"):
			configfile=v
		default:
		}
	}
	return fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n",redis_version,os,arch,executable,configfile)
}



func init() {
	rootCmd.AddCommand(redisCmd)
	redisCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	redisCmd.Flags().StringVarP(&Hosts,"host","H","","Set redis server host")
	redisCmd.Flags().IntVarP(&redis_port,"port","p",6379,"Set redis server port")
	redisCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	//redisCmd.Flags().StringVarP(&Username,"username","U","root","Set redis username")
	redisCmd.Flags().StringVarP(&Command,"command","c","","Set the command you want to execute")
	redisCmd.Flags().StringVarP(&Password,"password","P","","Set redis password")
	//redisCmd.Flags().StringVarP(&Userdict,"userdict","","","Set redis userdict path")
	redisCmd.Flags().StringVarP(&Passdict,"passdict","","","Set redis passworddict path")
	//redisCmd.MarkFlagRequired("host")
}
