package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/gookit/color"
	"github.com/malfunkt/iprange"
	"golang.org/x/net/proxy"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var Red = color.FgRed.Render
var Yellow = color.FgLightYellow.Render
var LightBlue = color.FgLightBlue.Render
var LightGreen = color.FgLightGreen.Render
var LightCyan = color.FgLightCyan.Render
var White=color.FgLightWhite.Render

type Mycolor func(a ...interface{}) string  //color类型，用于指定输出颜色
type Connect_method func(ip string ,port int) (string,int,error,[]string)//用于指定tcp连接函数（所有端口连接框架都用的portscan的，传入不同的connect方法来达到我们想要的目的

//建立tcp连接检测端口开放情况
func Connect(ip string, port int) (string, int, error,[]string) {
	conn,err:=Getconn(fmt.Sprintf("%v:%v",ip,port))
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		WebTitle(&HostInfo{Host: ip,Ports: fmt.Sprintf("%v",port),Timeout: Timeout*2})
		return ip,port,nil,nil
	}
	return ip, port, err,nil
}


func Connect_BannerScan(ip string,port int) (string,int,error,[]string) {
	conn,err:=Getconn(fmt.Sprintf("%v:%v",ip,port))
	if conn!=nil{
		conn.SetReadDeadline((time.Now().Add(Timeout)))
		reader:=bufio.NewReader(conn)
		s,_:=reader.ReadString('\r')
		s=strings.Replace(s,"\n","",-1)
		s="Banner:"+s
		a:=[]string{s}
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		WebTitle(&HostInfo{Host: ip,Ports: fmt.Sprintf("%v",port),Timeout: Timeout*2})
		return ip,port,err,a
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	return ip, port, err,nil
}

func Proxyconn() (proxy.Dialer,error) {
	if strings.ContainsAny(Proxy,"@")&&strings.Count(Proxy,"@")==1{
		info:=strings.Split(Proxy,"@")
		userpass:=strings.Split(info[0],":")
		auth:= proxy.Auth {userpass[0],userpass[1]}
		dialer,err:=proxy.SOCKS5("tcp",info[1],&auth,proxy.Direct)
		return dialer,err
	}else {
		if strings.ContainsAny(Proxy,":")&&strings.Count(Proxy,":")==1{
			dialer,err:=proxy.SOCKS5("tcp",Proxy,nil,proxy.Direct)
			//Inithttp(PocInfo{Timeout: Timeout,Num: Thread,Proxy: "http://"+Proxy})
			return dialer,err
			}
		}
	return nil,fmt.Errorf("proxy error")
}

func Getconn(addr string) (net.Conn,error) {
	if proxyconn!=nil{
		return proxyconn.Dial("tcp",addr)
	}else {
		return net.DialTimeout("tcp",addr,Timeout)
	}
}

//解析ip返回IP类型列表
func Parse_IP(ip_string string) ([]net.IP, error) {
	list, err := iprange.ParseList(ip_string)
	if err != nil {
		return nil, err
	}
	iplist := list.Expand()
	return iplist, nil
}

//解析端口
func Parse_Port(selection string) ([]int, error) {
	ports := make([]int, 0)
	if selection == "" {
		return ports, nil
	}

	ranges := strings.Split(selection, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("Invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("Invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports = append(ports, i)
			}

		} else {
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", r)
			} else {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}

//获取字符串中两个子字符串中间的字符串
//func GetBetween(str, starting, ending string) string {
//	s := strings.Index(str, starting)
//	if s < 0 {
//		return ""
//	}
//	s += len(starting)
//	e := strings.Index(str[s:], ending)
//	if e < 0 {
//		return ""
//	}
//	return str[s : s+e]
//}

//输出
func Output(s string,c Mycolor) {
	if Output_result{
		fmt.Print(c(s))
		file,err:=os.OpenFile(Path_result,os.O_APPEND|os.O_WRONLY,0666)
		Checkerr(err)
		defer file.Close()
		file.WriteString(s)
	}else {
		fmt.Print(c(s))
	}
	if Log{
		_,err:=os.Stat("log.txt")
		if err!=nil{
			CreatFile(true,"log.txt")
		}
		file,err:=os.OpenFile("log.txt",os.O_APPEND|os.O_WRONLY,0666)
		defer file.Close()
		Checkerr(err)
		file.Write([]byte(s))
	}
}

//创建文件
func CreatFile(b bool,filename string)  {
	if b{
		file,err:=os.Create(filename)
		Checkerr(err)
		defer file.Close()
	}
}

//检查错误
func Checkerr(err error) {
	if err != nil {
		fmt.Println(Red("ERROE:", err))
	}
}

func Checkerr_exit(err error) {
	if err != nil {
		fmt.Println(Red("ERROE:", err))
		os.Exit(0)
	}
}

//输出时间间隔和脚本结束时间
func Output_endtime(start time.Time)  {
	Output(fmt.Sprintf("\n%v\nTime consuming:%v\n\n", string(time.Now().AppendFormat([]byte("\rEnd time:"), l1)), time.Since(start)),LightCyan)
}

//输出扫描信息
func PrintScanBanner(mode string)  {
	if Proxy!=""{
		proxyconn,_=Proxyconn()
		if proxyconn==nil{
			Checkerr_exit(fmt.Errorf("proxy error"))
		}
	}
	Inithttp(PocInfo{Timeout: Timeout,Num: Thread})
	output_verbose:= func() {
		if Verbose {
			Output("Verbose:Show verbose\n",LightCyan)
		} else {
			Output("Verbose:Don't show verbose\n",LightCyan)
		}
	}
	output_pingbefor:= func() {
		if pingbefore {
			Output(fmt.Sprintf("Ping befor portscan\n"),LightCyan)
		} else {
			Output(fmt.Sprintf("Not ping befor portscan\n"),LightCyan)
		}
	}
	output_scan:= func() {
		Output(fmt.Sprintf("%s\nThe number of threads:%v\nTime delay:%v\nTraget:%v\n", string(time.Now().AppendFormat([]byte("Start time:"), l1)), Thread, Timeout, Hosts),LightCyan)
	}
	output_file:= func() {
		if Output_result{
			Output(fmt.Sprintf("Save result file:%v\n",Path_result),LightCyan)
		}
	}
	output_log:= func() {
		if Log{
			Output("Save scan log in log.txt\n",LightCyan)
		}
	}
	output_banner:= func() {
		if banner{
			Output("Output bannner infomation\n",LightCyan)
		}
	}
	output_command:= func() {
		if Command!=""{
			Output(fmt.Sprintf("Command executed:%v\n",Command),LightCyan)
		}
	}
	output_burpthread:= func() {
		Output(fmt.Sprintf("The number of burp threads:%v\n",burpthread),LightCyan)
	}
	switch mode {
	case "ps":
		Output("\nMode:portscan\n",Red)
		output_scan()
		output_verbose()
		output_pingbefor()
		output_banner()
		output_file()
		output_log()
		fmt.Println()
	case "ping":
		Output("\nMode:ping discover\n",Red)
		output_scan()
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	case "nc":
		Output("\nMode:nc\n",Red)
		Output(fmt.Sprintf("%s\n", string(time.Now().AppendFormat([]byte("Start time:"), l1))),LightCyan)
		if listen {
			Output(fmt.Sprintf("Listen on %v\n\n", Addr),LightCyan)
		} else {
			Output(fmt.Sprintf("Connect to %v\n\n", Addr),LightCyan)
		}
	case "socks":
		Output("\nMode:Socks5 server\n",Red)
		Output(fmt.Sprintf("Listen addr: %v\n\n",Addr),LightCyan)
	case "SocksScan":
		Output("\nMode:Proxy find\n",Red)
		output_scan()
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	case "ssh":
		Output("\nMode:ssh\n",Red)
		if burp{
			Output("SSH mode:burp\n",Red)
		}else {Output("SSH mode:login\n",Red)}
		output_scan()
		Output(fmt.Sprintf("The number of burp threads: 10 \n"),LightCyan)
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	case "mysql":
		Output("\nMode:mysql\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "mssql":
		Output("\nMode:mssql\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "redis":
		Output("\nMode:redis\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "netbios":
		Output("\nMode:netbios\n",Red)
		output_scan()
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	case "snmp":
		Output("\nMode:snmp\n",Red)
		output_scan()
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	case "postgres":
		Output("\nMode:postgres\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "all":
		Output("\nMode:all\n",Red)
		output_scan()
		output_verbose()
		output_pingbefor()
		output_file()
		output_log()
		fmt.Println()
	case "ftp":
		Output("\nMode:ftp\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "mongodb":
		Output("\nMode:mongo\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_log()
		output_command()
		fmt.Println()
	case "httpserver":
		Output("\nMode:httpserver\n",Red)
		Output(fmt.Sprintf("%s\n", string(time.Now().AppendFormat([]byte("Start time:"), l1))),LightCyan)
		Output(fmt.Sprintf("Listen on %v\n", httpserveraddr),LightCyan)
		Output(fmt.Sprintf("root directory：%v\n", dir),LightCyan)
		if Username==""&&Password==""{
			Output("No authentication required\n",LightCyan)
		}else {
			Output("Requires authentication\n",LightCyan)
		}
	case "ms17010":
		Output("\nMode:ms17_010\n",Red)
		output_scan()
		output_verbose()
		output_file()
		output_log()
		fmt.Println()
	}
}

func GetHost()  {
	switch  {
	case Hostfile!=""&&Hosts!="":
		hostlist,err:=ReadFile(Hostfile)
		Checkerr_exit(err)
		Hosts=Hosts+","+strings.Join(hostlist,",")
	case Hostfile!="":
		hostlist,err:=ReadFile(Hostfile)
		Checkerr_exit(err)
		Hosts=strings.Join(hostlist,",")
	case Hosts==""&&Hostfile=="":
		Checkerr_exit(fmt.Errorf("This module must be required --host or --hostfile\nUse \"zscan modename -h\" get some help"))
	default:
	}
}


func ReadFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var result []string
	for scanner.Scan() {
		passwd := strings.TrimSpace(scanner.Text())
		if passwd != "" {
			result = append(result, passwd)
		}
	}
	return result, err
}

func sortip(iplist []net.IP) []net.IP {
	sort.Slice(iplist, func(i, j int) bool {
		return bytes.Compare(iplist[i], iplist[j]) < 0
	})
	return iplist
}

func sortip_string(iplist []string) []net.IP {
	iplist_ip:=[]net.IP{}
	for _,i:=range iplist{
		iplist_ip=append(iplist_ip,net.ParseIP(i))
	}
	iplist_ip=sortip(iplist_ip)
	return iplist_ip
}

func contains(s string,list []string) bool {
	for _,i:=range list{
		if s==i{
			return true
		}
	}
	return false
}

func RemoveRepByMap(slc []string) []string {
	result := []string{}
	tempMap := map[string]byte{}  // 存放不重复主键
	for _, e := range slc{
		l := len(tempMap)
		tempMap[e] = 0
		if len(tempMap) != l{  // 加入map后，map长度变化，则元素不重复
			result = append(result, e)
		}
	}
	return result
}
