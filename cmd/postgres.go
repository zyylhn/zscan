package cmd

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"time"
)


var postgre_port int

var postgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "burp postgres username and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("postgres")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		postgres()
	},
}

func postgres()  {
	burp_postgres()
}

func burp_postgres()  {
	GetHost()
	if Command!=""{
		err,_,_:=postgres_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="postgres"
	}
	ips:= Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{postgre_port},Connectpostgres,true)
	_=aliveserver.Run()
}

func Connectpostgres(ip string, port int) (string, int, error,[]string) {
	conn, err := Getconn( ip, port)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("Start burp postgres : ",ip))
		_,f,_:=postgres_auth("postgres","",ip)
		if f{
			Output(fmt.Sprintf("%v burp success:%v No authentication\n","postgres",ip),LightGreen)
			return ip,port,nil,[]string{"No authentication"}
		}
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,postgres_auth,burpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func postgres_auth(username,password,ip string) (error, bool,string) {
	DSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d", username, password, ip, postgre_port, Timeout)
	db, err := sql.Open("postgres", DSN)
	if err == nil {
		err = db.Ping()
		if err == nil {
			return nil,true,"postgres"
		}

		db.Close()
	}
	return err,false,"postgres"
}

func init() {
	blastCmd.AddCommand(postgresCmd)
	postgresCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	postgresCmd.Flags().StringVarP(&Hosts,"host","H","","Set postgres server host")
	postgresCmd.Flags().IntVarP(&postgre_port,"port","p",5432,"Set postgres server port")
	postgresCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	postgresCmd.Flags().StringVarP(&Username,"username","U","","Set postgres username")
	postgresCmd.Flags().StringVarP(&Password,"password","P","","Set postgres password")
	postgresCmd.Flags().StringVarP(&Userdict,"userdict","","","Set postgres userdict path")
	postgresCmd.Flags().StringVarP(&Passdict,"passdict","","","Set postgres passworddict path")
}