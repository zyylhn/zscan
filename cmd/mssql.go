
package cmd

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/spf13/cobra"
	"time"
)


var mssql_port int
// mssqlCmd represents the mssql command
var mssqlCmd = &cobra.Command{
	Use:   "mssql",
	Short: "burp mssql username and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("mssql")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		mssql()
	},
}

func mssql()  {
	burp_mssql()
}

func burp_mssql()  {
	GetHost()
	if Command!=""{
		err,_,_:=mssql_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="sa,Admin,Administrator"
	}
	ips:= Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{mssql_port},Connectmssql,true)
	_=aliveserver.Run()
}

func Connectmssql(ip string, port int) (string, int, error,[]string) {
	conn, err := Getconn( ip, port)
	defer func() {
		if conn != nil {
			_ = conn.Close()
			fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
			fmt.Println(Yellow("Start burp mssql : ",ip))
			startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,mssql_auth,burpthread)
			startburp.Run()
		}
	}()
	return ip, port, err,nil
}
func mssql_auth(user ,pass ,addr string) ( error,bool,string) {
	connString := fmt.Sprintf("sqlserver://%v:%v@%v:%v/?connection+timeout=%v&encrypt=disable", user, pass,addr,mssql_port,5)
	db, err := sql.Open("mssql", connString)
	if err == nil {
		defer func() {
			_=db.Close()
		}()
		err = db.Ping()
		if err == nil {
			return nil,true,"mssql"
		}
		db.Close()
	}
	return err,false,"mssql"
}

func init() {
	blastCmd.AddCommand(mssqlCmd)
	mssqlCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	mssqlCmd.Flags().StringVarP(&Hosts,"host","H","","Set mysql server host")
	mssqlCmd.Flags().IntVarP(&mssql_port,"port","p",1433,"Set mysql server port")
	mssqlCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	mssqlCmd.Flags().StringVarP(&Username,"username","U","","Set mysql username")
	mssqlCmd.Flags().StringVarP(&Password,"password","P","","Set mysql password")
	mssqlCmd.Flags().StringVarP(&Userdict,"userdict","","","Set mysql userdict path")
	mssqlCmd.Flags().StringVarP(&Passdict,"passdict","","","Set mysql passworddict path")
	//mssqlCmd.MarkFlagRequired("host")
}
