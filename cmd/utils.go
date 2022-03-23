package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gookit/color"
	"github.com/malfunkt/iprange"
	"github.com/projectdiscovery/cdncheck"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	conn,err:=Getconn(ip,port)
	if conn != nil {
		_ = conn.Close()
		Output(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port),White)
		if !webscan{
			httpinfo,_:=WebTitle(&HostInfo{Host: ip,Ports: fmt.Sprintf("%v",port),Timeout: Timeout*2})
			if httpvulscan&&httpinfo!=nil{
				HttpVulScan(httpinfo)
			}
		}
		return ip,port,nil,nil
	}
	return ip, port, err,nil
}


func Connect_BannerScan(ip string,port int) (string,int,error,[]string) {
	conn,err:=Getconn(ip,port)
	if conn!=nil{
		conn.SetReadDeadline((time.Now().Add(Timeout)))
		reader:=bufio.NewReader(conn)
		s,_:=reader.ReadString('\r')
		s=strings.Replace(s,"\n","",-1)
		s="Banner:"+s
		a:=[]string{s}
		Output(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port),White)
		if !webscan{
			httpinfo,_:=WebTitle(&HostInfo{Host: ip,Ports: fmt.Sprintf("%v",port),Timeout: Timeout*2})
			if httpvulscan&&httpinfo!=nil{
				HttpVulScan(httpinfo)
			}
		}
		return ip,port,err,a
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	return ip, port, err,nil
}

func ConnectSyn(dstIp string,dstPort int) (string,int,error,[]string) {
	srcIp, srcPort, err := localIPPort(net.ParseIP(dstIp))
	dstAddrs, err := net.LookupIP(dstIp)
	if err != nil {
		return dstIp, 0, err,nil
	}

	dstip := dstAddrs[0].To4()
	var dstport layers.TCPPort
	dstport = layers.TCPPort(dstPort)
	srcport := layers.TCPPort(srcPort)

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		SYN:     true,
	}
	err = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return dstIp, 0, err,nil
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return dstIp, 0, err,nil
	}
	defer conn.Close()

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return dstIp, 0, err,nil
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(Timeout)); err != nil {
		return dstIp, 0, err,nil
	}

	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return dstIp, 0, err,nil
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						Output(fmt.Sprintf("\rFind port %v:%v\r\n", dstIp, dstPort),White)
						return dstIp, dstPort, err,nil
					} else {
						return dstIp, 0, err,nil
					}
				}
			}
		}
	}
}

func localIPPort(dstip net.IP) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":54321")
	if err != nil {
		return nil, 0, err
	}
	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	return nil, -1, err
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

func Getconn(ip string,port int) (net.Conn,error) {
	if port==0{
		if proxyconn!=nil{
			return proxyconn.Dial("tcp",ip)
		}else {
			return net.DialTimeout("tcp",ip,Timeout)
		}
	}else {
		if proxyconn!=nil{
			return proxyconn.Dial("tcp",fmt.Sprintf("%v:%v",ip,port))
		}else {
			return net.DialTimeout("tcp",fmt.Sprintf("%v:%v",ip,port),Timeout)
		}
	}
}

//解析ip返回IP类型列表
func Parse_IP(ip_string string) []string {
	var re []string
	if strings.Contains(ip_string,","){
		iplist:=strings.Split(ip_string,",")
		for _,v:=range iplist{
			ip,err:=iprangeParse(v)
			if err!=nil{
				fmt.Println(Red(err))
			}else {
				re= append(re, ip...)
			}
		}
	}else {
		ip,err:=iprangeParse(ip_string)
		if err!=nil{
			fmt.Println(Red(err))
		}else {
			re= append(re, ip...)
		}
	}
	return re
}

func iprangeParse(ip string) ([]string,error) {
	var re []string
	list, err := iprange.ParseList(ip)
	if err != nil {                   //解析不了的ip先判断是不是ipv6
		if isIPv6(ip){
			return []string{Parse_IPv6(ip)},nil
		}
		return nil, fmt.Errorf("IP format error,check the entered IP address:%v",ip)
	}
	iplist := list.Expand()
	for _,i:=range iplist{
		re= append(re, i.String())
	}
	return re, nil
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

//输出
func Output(s string,c Mycolor) {
	fmt.Print(c(s))
	OutputChan<-s
}

//创建文件,如果没有指定要存的文件名默认用host名存
func CreatFile()  {
	if Hosts!=""&&Path_result=="result.txt"{
		new_filename:=filename_filter(Hosts)+".txt"
		Path_result=new_filename
	}
	//如果文件不存在则创建文件
	_,err:=os.Stat(Path_result)
	if err!=nil{
		file,err:=os.Create(Path_result)
		Checkerr(err)
		defer file.Close()
		}
}

func filename_filter(filename string)string{
	f:= func(c rune) rune{
		special:="\\/:*?<>|"
		if strings.Contains(special,string(c)){
			return '_'
		}
		return c
	}
	return strings.Map(f,filename)
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

func SaveInit()  {
	CreatFile()
	OutputChan=make(chan string)
	go func() {
		file,err:=os.OpenFile(Path_result,os.O_APPEND|os.O_WRONLY,0666)
		defer file.Close()
		Checkerr(err)
		for outputre:=range OutputChan{
			file.Write([]byte(outputre))
			if strings.Contains(outputre,"consuming"){
				runmod=true
				stopchan<-1
				return
			}
		}
	}()
}
//输出扫描信息
func PrintScanBanner(mode string)  {
	output_verbose:= func() {
		if Verbose {
			Output("Verbose:Show verbose\n",LightCyan)
		} else {
			Output("Verbose:Don't show verbose\n",LightCyan)
		}
	}
	output_pingbefor:= func() {
		if !pingbefore {
			Output(fmt.Sprintf("Ping befor portscan\n"),LightCyan)
		} else {
			Output(fmt.Sprintf("Not ping befor portscan\n"),LightCyan)
		}
	}
	output_scan:= func() {
		Output(fmt.Sprintf("%s\nThe number of threads:%v\nTime delay:%v\nTraget:%v%v\n", string(time.Now().AppendFormat([]byte("Start time:"), l1)), Thread, Timeout, Hosts,TargetUrl),LightCyan)
	}
	output_file:= func() {
		Output(fmt.Sprintf("Save result file:%v\n",Path_result),LightCyan)
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
	output_pocscanthread:= func() {
		Output(fmt.Sprintf("The number of poc scan threads:%v\n",PocThread),LightCyan)
	}
	output_pocinfo:= func() {
		if Pocpath==""{
			Output("Use built in poc\n",LightCyan)
		}else {
			Output(fmt.Sprintf("Use External poc dir: %v\n",Pocpath),LightCyan)
		}
		if PocName!=""{
			Output(fmt.Sprintf("Poc name %v\n",PocName),LightCyan)
		}
	}
	switch mode {
	case "ps":
		Output("\nMode:portscan\n",Red)
		output_scan()
		output_verbose()
		output_pingbefor()
		output_banner()
		output_file()
		fmt.Println()
	case "ping":
		Output("\nMode:ping discover\n",Red)
		output_scan()
		output_verbose()
		output_file()
		fmt.Println()
	case "socks":
		Output("\nMode:Socks5 server\n",Red)
		Output(fmt.Sprintf("Listen addr: %v\n\n",Addr),LightCyan)
	case "SocksScan":
		Output("\nMode:Proxy find\n",Red)
		output_scan()
		output_verbose()
		output_file()
		fmt.Println()
	case "ssh":
		Output("\nMode:ssh\n",Red)
		output_scan()
		Output(fmt.Sprintf("The number of burp threads: 10 \n"),LightCyan)
		output_verbose()
		output_file()
		fmt.Println()
	case "mysql":
		Output("\nMode:mysql\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "mssql":
		Output("\nMode:mssql\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "redis":
		Output("\nMode:redis\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "netbios":
		Output("\nMode:netbios\n",Red)
		output_scan()
		output_verbose()
		output_file()
		fmt.Println()
	case "snmp":
		Output("\nMode:snmp\n",Red)
		output_scan()
		output_verbose()
		output_file()
		fmt.Println()
	case "postgres":
		Output("\nMode:postgres\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "all":
		Output("\nMode:all\ndont't have ssh\n",Red)
		output_scan()
		output_verbose()
		output_pingbefor()
		output_file()
		fmt.Println()
	case "ftp":
		Output("\nMode:ftp\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "mongodb":
		Output("\nMode:mongo\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
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
		fmt.Println()
	case "ldap":
		Output("\nMode:ldap\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		output_command()
		fmt.Println()
	case "rdp":
		Output("\nMode:rdp\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		fmt.Println()
	case "poc":
		Output("\nMode:poc\n",Red)
		Output(fmt.Sprintf("%s\nHttp time delay:%v(3*Timeout)\nTraget:%v%v\n", string(time.Now().AppendFormat([]byte("Start time:"), l1)), Timeout*3, Hosts,TargetUrl),LightCyan)
		output_pocscanthread()
		output_pocinfo()
		output_file()
		fmt.Println()
	case "smb":
		Output("\nMode:smb\n",Red)
		output_scan()
		output_burpthread()
		output_verbose()
		output_file()
		fmt.Println()
	}
}

func GetHost()  {
	switch  {
	case Hostfile!=""&&Hosts!="":
		hostlist,err:=ReadFile(Hostfile)
		Checkerr_exit(err)
		hostlist=RemoveRepByMap(hostlist)
		if len(hostlist)!=0{
			if isDomain(hostlist[0]){
				hostlist=Getiplistfromurl(hostlist)
			}
		}
		Hosts=Hosts+","+strings.Join(hostlist,",")
	case Hostfile!=""&&Hosts=="":
		hostlist,err:=ReadFile(Hostfile)
		Checkerr_exit(err)
		hostlist=RemoveRepByMap(hostlist)
		if len(hostlist)!=0{
			if isDomain(hostlist[0]){
				hostlist=Getiplistfromurl(hostlist)
			}
		}
		Hosts=strings.Join(hostlist,",")
	case Hosts!=""&&Hostfile=="":
		if strings.Contains(Hosts,","){
			hostlist:=strings.Split(Hosts,",")
			if isDomain(hostlist[0]){
				hostlist=Getiplistfromurl(hostlist)
				Hosts=strings.Join(hostlist,",")
			}
		}else {
			if isDomain(Hosts){
				hostlist:=Getiplistfromurl([]string{Hosts})
				if len(hostlist)!=0{
					Hosts=strings.Join(hostlist,",")
				}
			}
		}
	case Hosts==""&&Hostfile=="":
		Checkerr_exit(fmt.Errorf("This module must be required --host or --hostfile\nUse \"zscan modename -h\" get some help"))
	default:
	}
}

func Getiplistfromurl(list []string) []string {
	Output("Start resolving domain names\n",LightCyan)
	client, err := cdncheck.NewWithCache()
	if err != nil {
		log.Fatal(err)
	}
	var re []string
	var result []string
	var wg sync.WaitGroup
	listchan:=make(chan string,100)
	for i:=0;i<Thread;i++{
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l:=range listchan{
				iplist,err:=net.LookupHost(l)
				Checkerr(err)
				if iplist!=nil&&len(iplist)==1{
					for _,ip:=range iplist{
						re=append(re,ip)
						Output(fmt.Sprintf("%v : %v\n",l,ip),White)
					}
				}else if len(iplist)>1 {
					Output(fmt.Sprintf("%v has cdn\n",l),Yellow)
				}
			}
		}()
	}
	for _,domain:=range list{
		if strings.HasPrefix(domain,"http://"){
			domain=strings.TrimPrefix(domain,"http://")
		}
		if strings.HasPrefix(domain,"https://"){
			domain=strings.TrimPrefix(domain,"https://")
		}
		listchan<-domain
	}
	close(listchan)
	wg.Wait()
	re=RemoveRepByMap(re)
	Output("Start to remove known CDNS\n",LightCyan)
	for _,ip:=range re{
		success:=FilterCdn(ip,client)
		if success!=""&&!strings.Contains(ip,":"){
			result= append(result, success)
		}else {
			Output(fmt.Sprintf("%v is cdn\n",ip),Yellow)
		}
	}
	Output("all target\n",LightCyan)
	for _,v:=range result{
		Output(v+"\n",White)
	}
	return result
}

func FilterCdn(ip string,client *cdncheck.Client) string {
	if found,_ ,err := client.Check(net.ParseIP(ip)); found && err == nil {
		return ""
	}
	return ip
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

func Parse_IPv6(ipstring string) string {
	var ipv6 string
	if ip:=net.ParseIP(ipstring);ip!=nil{
		ipv6="["+ip.String()+"]"
	}
	return ipv6
}

func isDomain(domain string) bool {
	var rege = regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+.?`)
	if strings.HasPrefix(domain,"http"){
		return true
	}
	if net.ParseIP(domain)!=nil{
		return false
	}
	if _,err:=iprangeParse(domain);err==nil{
		return false
	}

	return rege.MatchString(domain)
}

func isIPv6(ipv6 string) bool {
	ip:=net.ParseIP(ipv6)
	if ip==nil{
		return false
	}
	for i:=0;i<len(ipv6);i++{
		if ipv6[i]==':'{
			return true
		}
		continue
	}
	return false
}