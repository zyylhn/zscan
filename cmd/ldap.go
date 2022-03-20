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
	if Username==""{
		Username="Administrator"
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{ldap_port},Connectldap,true)
	_=aliveserver.Run()
}

func Connectldap(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn( ip, port)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("\rStart burp ldap : ",ip))
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,ldap_auth,burpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func ldap_auth(username,password,ip string) (error,bool,string) {
	_,err:=LoginBind(username,password,ip)
	if err!=nil{
		return err,false,"ldap"
	}else {
		return nil,true,"ldap"
	}
}

func LoginBind(ldapUser, ldapPassword string,ip string) (*ldap.Conn, error) {
	conn,err:=Getconn(ip, ldap_port)
	l:=ldap.NewConn(conn,false)
	l.Start()
	if err != nil {
		return nil, err
	}
	err = l.Bind(ldapUser,ldapPassword)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func init() {
	blastCmd.AddCommand(ldapCmd)
	ldapCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	ldapCmd.Flags().StringVarP(&Hosts,"host","H","","Set ldap server host")
	ldapCmd.Flags().IntVarP(&ldap_port,"port","p",389,"Set ldap server port")
	ldapCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	ldapCmd.Flags().StringVarP(&Username,"username","U","","Set ldap username")
	ldapCmd.Flags().StringVarP(&Password,"password","P","","Set ldap password")
	ldapCmd.Flags().StringVarP(&Userdict,"userdict","","","Set ldap userdict path")
	ldapCmd.Flags().StringVarP(&Passdict,"passdict","","","Set ldap passworddict path")
}
