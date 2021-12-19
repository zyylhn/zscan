package cmd

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	"time"
)

var ldap_port int
// ldapCmd represents the ldap command
var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "burp ldap and query",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result,Path_result)
		PrintScanBanner("ldap")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		ldapmode()
	},
}

func ldapmode()  {
	burp_ldap()
}

func burp_ldap()  {
	GetHost()
	if Command!=""{
		err,_,_:=ldap_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="Administrator"
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{ldap_port},Connectldap,true)
	_=aliveserver.Run()
}

func Connectldap(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn(fmt.Sprintf("%s:%d", ip, port))
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("\rStart burp ldap : ",ip))
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,ldap_auth,burpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func ldap_auth(username,password,addr string) (error,bool,string) {
	//l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", addr, ldap_port))
	conn,err:=Getconn(fmt.Sprintf("%s:%d", addr, ldap_port))
	l:=ldap.NewConn(conn,false)
	l.Start()
	if err==nil{
		defer l.Close()
		err = l.Bind(username,password)
		if err==nil{
			if Command!=""{
				fmt.Println("exec command")
			}
			return nil,true,"ldap"
		}
		return nil,false,"ldap"
	}
	return err,false,"ldap"
}

func init() {
	rootCmd.AddCommand(ldapCmd)
	ldapCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	ldapCmd.Flags().StringVarP(&Hosts,"host","H","","Set ldap server host")
	ldapCmd.Flags().IntVarP(&ldap_port,"port","p",389,"Set ldap server port")
	ldapCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	ldapCmd.Flags().StringVarP(&Username,"username","U","","Set ldap username")
	ldapCmd.Flags().StringVarP(&Command,"command","c","","Set the command you want to sql_execute")
	ldapCmd.Flags().StringVarP(&Password,"password","P","","Set ldap password")
	ldapCmd.Flags().StringVarP(&Userdict,"userdict","","","Set ldap userdict path")
	ldapCmd.Flags().StringVarP(&Passdict,"passdict","","","Set ldap passworddict path")
}
