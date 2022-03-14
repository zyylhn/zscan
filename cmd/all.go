package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

var notburp bool

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Use all scan mode（don't hava ssh mod）",
	PreRun: func(cmd *cobra.Command, args []string) {
		//CreatFile(Output_result,Path_result)
		PrintScanBanner("all")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		allmode()
	},
}

func allmode()  {
	GetHost()
	if !pingbefore {
		Hosts = ping_discover()
	}
	if Hosts==""{
		Output("Don't have living host,can use --noping test",Red)
		return
	}
	ips, err := Parse_IP(Hosts)
	Checkerr_exit(err)
	//if len(ips)>500&&ps_port==default_port{
	//	ps_port=little_port
	//}
	if ps_port=="l"{
		ps_port=little_port
	}
	ports, err := Parse_Port(ps_port)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,ports,Connectall,true)
	Output("Start port scan\n",LightCyan)
	r:=aliveserver.Run()
	Printresult(r)
}

func Connectall(ip string, port int) (string, int, error,[]string) {
	var r []string //返回从该端口获取的信息
	conn,err:=Getconn(ip,port)
	if conn != nil {
		defer conn.Close()
		addr:=fmt.Sprintf("%v:%v",ip,port)
		Output(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port),White)
		switch port {
		//case 22:
		//	if !notburp{
		//		if Verbose{
		//			fmt.Println(Yellow("\rStart burp ssh : ",ip,":",port))
		//		}
		//		name:="root,admin,ssh"
		//		if Username!=""{
		//			name=Username
		//		}
		//		_,f,_:=ssh_auto("root","Ksdvfjsxc",ip)
		//		if f{
		//			Output(fmt.Sprintf("[-]%v Don't allow root login:%v \n","ssh",ip),Yellow)
		//			var re []string
		//			if strings.Contains(Username,"root"){
		//				sl:=strings.Split(Username,",")
		//				for _,i:=range sl{
		//					if i=="root"{
		//						continue
		//					}
		//					re=append(re,i)
		//				}
		//			}
		//			Username=strings.Join(re,",")
		//		}
		//		startburp:=NewBurp(Password,name,Userdict,Passdict,ip,ssh_auto,10)
		//		relust:=startburp.Run()
		//		if relust!=""{
		//			return ip,port,nil,[]string{relust}
		//		}
		//	}
		//	return ip,port,nil,nil
		case 3306:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp mysql : ",ip,":",port))
				}
				_,f,_:=mysql_auth("asdasd","zxczxc",ip)
				if f{
					Output(fmt.Sprintf("[+]%v burp success:%v No authentication\n","mysql",ip),LightGreen)
					interested_result.Store(addr,"mysql no authentication")
					return ip,port,nil,[]string{"No authentication"}
				}
				user:="root,mysql"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,mysql_auth,100)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 6379:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp redis : ",ip,":",port))
				}
				_,f,_:=redis_auth("","",ip)
				if f{
					Output(fmt.Sprintf("[+]%v burp success:%v No authentication\n","redis",ip),LightGreen)
					interested_result.Store(addr,"resis no authentication")
					return ip,port,nil,[]string{"No authentication"}
				}
				startburp:=NewBurp(Password,"","",Passdict,ip,redis_auth,100)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 1433:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp mssql : ",ip,":",port))
				}
				user:="sa,admin,Administrator"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,mssql_auth,100)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 3389:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp rdp : ",ip,":",port))
				}
				user:="admin,Administrator"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,rdp_auth,50)
				relust:=startburp.Run()
				if relust!="" {
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 5432:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp postgres : ",ip,":",port))
				}
				_,f,_:=postgres_auth("postgres","",ip)
				if f{
					Output(fmt.Sprintf("%v burp success:%v No authentication\n","postgres",ip),LightGreen)
					interested_result.Store(addr,"postgres no authentication")
					return ip,port,nil,[]string{"No authentication"}
				}
				user:="postgres"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,postgres_auth,100)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(ip,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 21:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp ftp : ",ip,":",port))
				}
				_,f,_:=ftp_auth("ftp","asdasd",ip)
				if f{
					Output(fmt.Sprintf("%v burp success:%v No authentication\n","ftp",ip),LightGreen)
					interested_result.Store(addr,"ftp no authentication")
					return ip,port,nil,[]string{"No authentication"}
				}
				user:="ftp,anonymous,root"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,ftp_auth,burpthread)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
			}
			return ip,port,nil,nil
		case 27017:
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp mongodb : ",ip,":",port))
				}
				_,f,_:=mongodb_auth("","",ip)
				if f{
					Output(fmt.Sprintf("[+]%v burp success:%v No authentication\n","mongodb",ip),LightGreen)
					interested_result.Store(addr,"mongodb no authentication")
					return ip,port,nil,[]string{"No authentication"}
				}
				user:="mongo,root,mongodb"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,mongodb_auth,burpthread)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store(addr,relust)
					return ip,port,nil,[]string{relust}
				}
				return ip,port,nil,nil
			}
		case 389:
			interested_result.Store(addr,"It may be a domain controller")
			//if !notburp{
			//	if Verbose{
			//		fmt.Println(Yellow("\rStart burp ldap : ",ip))
			//	}
			//	user:="Administrator,admin"
			//	if Username!=""{
			//		user=Username
			//	}
			//	startburp:=NewBurp(Password,user,Userdict,Passdict,ip,ldap_auth,burpthread)
			//	relust:=startburp.Run()
			//	if relust!=""{
			//		interested_result.Store(addr,relust)
			//		return ip,port,nil,[]string{relust}
			//	}
			//}
			return ip,port,nil,nil
		case 7890:
			b,s:=Socks5Find(conn)
			if b {
				Output(fmt.Sprintf("\r%v\t%v:%v \n",s,ip,port),LightGreen)
				r=[]string{s}
				interested_result.Store(addr,s)
				return ip, port, nil,r
			}else {
				return ip,port,nil,nil
			}
		case 10808:
			b,s:=Socks5Find(conn)
			if b {
				Output(fmt.Sprintf("\r%v\t%v:%v \n",s,ip,port),LightGreen)
				r=[]string{s}
				interested_result.Store(addr,s)
				return ip, port, nil,r
			}else {
				return ip,port,nil,nil
			}
		case 1089:
			b,s:=Socks5Find(conn)
			if b {
				Output(fmt.Sprintf("\r%v\t%v:%v \n",s,ip,port),LightGreen)
				r=[]string{s}
				interested_result.Store(addr,s)
				return ip, port, nil,r
			}else {
				return ip,port,nil,nil
			}
		case 445:
			_,smbRes:=smbinfo(conn)
			_,_,_,r=Connect17010(ip,port)
			for _,i:=range r{
				if strings.Contains(i,"MS17-010"){
					interested_result.Store("17010："+addr,i)
				}
				smbRes=append(smbRes,i)
			}
			if !notburp{
				if Verbose{
					fmt.Println(Yellow("\rStart burp rdp : ",ip,":",port))
				}
				user:="admin,Administrator"
				if Username!=""{
					user=Username
				}
				startburp:=NewBurp(Password,user,Userdict,Passdict,ip,smb_auth,100)
				relust:=startburp.Run()
				if relust!=""{
					interested_result.Store("smb："+addr,relust)
				}
				smbRes=append(smbRes,relust)
			}
			return ip,port,nil,smbRes
		case 135:
			_,oxidres:=oxidIpInfo(conn)
			return ip,port,nil,oxidres
		case 139:
			nbname, _ := netBIOS(ip)
			if nbname.msg != "" {
				return ip, port, nil, []string{nbname.msg}
			}
		default:
			httpinfo,_:=WebTitle(&HostInfo{Host: ip,Ports: fmt.Sprintf("%v",port),Timeout: Timeout})
			if !httpvulscan&&httpinfo!=nil{
				HttpVulScan(httpinfo)
			}
		}
	}
	return ip, port, err,r
}


func init() {
	rootCmd.AddCommand(allCmd)
	allCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	allCmd.Flags().BoolVarP(&useicmp,"icmp","i",false,"Icmp packets are sent to check whether the host is alive(need root)")
	allCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap) eg:192.168.1.1/24,172.16.95.1-100,127.0.0.1")
	allCmd.Flags().StringVarP(&ps_port, "port", "p", default_port, "Set `port` eg:1-1000,3306,3389 or use \" zscan all -p l\" ) to scan less port（thirty port）")
	allCmd.Flags().BoolVar(&pingbefore, "noping", false, " Not ping before port scanning")
	allCmd.Flags().StringVarP(&Password,"password","P","","Set postgres password")
	allCmd.Flags().StringVarP(&Passdict,"passdict","","","Set postgres passworddict path")
	allCmd.Flags().StringVarP(&Username,"username","U","","Set user name")
	allCmd.Flags().BoolVar(&notburp,"noburp",false,"Set postgres passworddict path")
	allCmd.Flags().BoolVar(&httpvulscan,"novulscan",false,"disable http vulnerability scan")
}
