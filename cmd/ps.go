package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"zscan/config"
	lib "zscan/poccheck"
)

var httptitle_result sync.Map
var httpvul_result sync.Map
var interested_result sync.Map
var pingbefore bool
var banner bool
var syn bool
var ps_port string
var webscan bool
var httpvulscan bool
var portscanCmd = &cobra.Command{
	Use:   "ps",
	Short: "Port Scan",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("ps")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		GetHost()
		if !pingbefore {
			Hosts = ping_discover()
		}
		if Hosts==""{
			Output("Don't have living host,can use --noping test",Red)
			return
		}
		ips:= Parse_IP(Hosts)
		if ps_port=="l"{
			ps_port=config.Little_port
		}
		ports, err := Parse_Port(ps_port)
		Checkerr(err)
		portscan(ips,ports)
	},
}


func portscan(ips []string,ports []int)  {
	var port_scan *PortScan
	if banner{
		port_scan=NewPortScan(ips,ports,Connect_BannerScan,true)
	}else if syn{
		port_scan=NewPortScan(ips,ports,ConnectSyn,true)
	} else {
		port_scan=NewPortScan(ips,ports,Connect,true)
	}
	Output("Start port scan\n",LightCyan)
	r:=port_scan.Run()
	Printresult(r)

}

type Openport struct {
	ip string   //ip地址
	port []int   //所有开启的端口
	banner map[int][]string  //端口号为key的banner信息
}


type PortScan struct {
	iplist []string
	ports []int
	wg sync.WaitGroup
	taskch chan map[string]int
	tcpconn Connect_method
	result map[string]*Openport
	portscan_result sync.Map
	tasknum float64
	donenum float64
	percent bool
}

func NewPortScan(iplist []string,ports []int,connect Connect_method,p bool) *PortScan {
	return &PortScan{iplist: iplist,ports: ports,taskch: make(chan map[string]int,Thread*2),tcpconn: connect,result: make(map[string]*Openport),tasknum: float64(len(iplist)*len(ports)),percent: p}
}

//端口扫描的开始函数，返回结果
func (p *PortScan) Run() map[string]*Openport {
	p.wg.Add(1)
	go p.Gettasklist()
	for i := 0; i < Thread; i++ {
		p.wg.Add(1)
		go p.Startscan()
	}
	if !No_progress_bar{
		if p.percent{
			go p.bar()
		}
	}
	p.wg.Wait()
	p.Getresult()
	return p.result
}

//获取任务列表
func (p *PortScan) Gettasklist()  {
	defer p.wg.Done()
	for _, port := range p.ports  {
		for _, ip := range p.iplist  {
			//fmt.Println(ip)
			ipPort := map[string]int{ip: port}
			//fmt.Println(ipPort)
			p.taskch <- ipPort
		}
	}
	close(p.taskch)
}

//扫描函数
func (p *PortScan) Startscan()  {
	defer p.wg.Done()
	for task := range p.taskch {
		for ip, port := range task {
			//fmt.Println(ip,port)
			_ = p.Saveresult(p.tcpconn(ip, port))
			p.donenum+=1
			//_ = err //dial tcp 172.16.95.1:3301: connect: connection refused
		}
	}
}

//将结果保存下来
func (p *PortScan) Saveresult(ip string, port int, err error,banner []string) error {
	if err != nil ||port==0{
		return err
	}
	if strings.HasPrefix(ip,"[")&&strings.HasSuffix(ip,"]"){
		ip=strings.Trim(ip,"[]")
	}
	v, ok := p.portscan_result.Load(ip)
	if ok {
		psresultlock.Lock()
		ports, ok1 := v.(map[int][]string)
		psresultlock.Unlock()
		if ok1 {
			ports[port]=banner
			p.portscan_result.Store(ip, ports)
			//fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port))) //扫描过程中输出扫描信息
		}
	} else {
		ports := make(map[int][]string, 0)
		ports[port]=banner
		p.portscan_result.Store(ip, ports)
		//fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port))) //扫描过程中输出扫描信息
	}
	return err
}

//将结果写到result中，用于返回值
func (p *PortScan) Getresult()  {
	p.portscan_result.Range(func(key, value interface{}) bool {
		v,ok:=value.(map[int][]string)
		if ok{
			port:=[]int{}
			for i,_:=range v{
				port=append(port,i)
			}
			sort.Ints(port)
			b:=make(map[int][]string)
			for _,i:=range port{
				b[i]=v[i]
			}
			//fmt.Println(Red(b))
			p.result[key.(string)]=&Openport{ip: key.(string),port:port,banner:b }
		}
		return true
	})
}

func (p *PortScan)bar()  {
	for  {
		for _, r := range `-\|/` {
			fmt.Printf("\r%c portscan:%4.2f%v %c", r,float64(p.donenum/p.tasknum*100),"%",r)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

//格式化输出ps模块的结果
func Printresult(r map[string]*Openport)  {
	Output("\r\n============================port result list=============================\n",LightGreen)
	Output(fmt.Sprintf("There are %v IP addresses in total\n",len(r)),LightGreen)
	realIPs := make([]net.IP, 0, len(r))
	for ip,_:=range r{
		realIPs = append(realIPs, net.ParseIP(ip))   //将ip放入列表做个排序
	}
	for _, i := range sortip(realIPs) {
		Output(fmt.Sprintf("Traget:%v\n", i), LightBlue)
		for _, p := range r[i.String()].port {
			if len(r[i.String()].banner[p])>0 {
				Output(fmt.Sprintf("  %v ", p), White)
				for _,j:=range r[i.String()].banner[p]{
					Output(fmt.Sprintf("\t%v\n",j), White)
				}
			}else {
				Output(fmt.Sprintf("  %v\n", p), White)
			}
		}
	}
	if !Mapisnil(httptitle_result){
		var titlelist []*HostInfo
		var nulltitlelist []*HostInfo
		Output("\r\n============================http result list=============================\n",LightGreen)
		httptitle_result.Range(func(key, value interface{}) bool {
			v,ok:=value.(*HostInfo)
			if ok{
				if v.Infostr!=nil{
					OutputHttp(v)
				}else if v.baseinfo.title!=""{
					titlelist=append(titlelist,v)
				}else {
					nulltitlelist=append(nulltitlelist,v)
				}
			}
			return true
		})
		for _,re:=range titlelist{
			OutputHttp(re)
		}
		for _,re:=range nulltitlelist{
			OutputHttp(re)
		}
	}
	if !Mapisnil(httpvul_result){
		Output("\r\n=========================http vulnerability list=========================\n",LightGreen)
		httpvul_result.Range(func(key, value interface{}) bool {
			v,ok:=value.(*lib.PocResult)
			if ok {
				OutputVul(v)
			}
			return true
		})
	}
	if !Mapisnil(interested_result){
		Output("\r\n=========================That might be of interest========================\n",LightGreen)
		interested_result.Range(func(key, value interface{}) bool {
			//fmt.Println(key,value)
			v,ok:=value.(string)
			if ok {
				Output(fmt.Sprintf("%v\t",key),White)
				Output(fmt.Sprintf("%v\n",v),LightGreen)
			}
			return true
		})
	}
}

func Mapisnil(p sync.Map) bool {
	is:=true
	p.Range(func(key, value interface{}) bool {
		if key!=nil{
			is=false
			return false
		}
		return true
	})
	return is
}

func init() {
	RootCmd.AddCommand(portscanCmd)
	portscanCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	portscanCmd.Flags().BoolVarP(&useicmp,"icmp","i",false,"Icmp packets are sent to check whether the host is alive(need root)")
	portscanCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap) eg:192.168.1.1/24,172.16.95.1-100,127.0.0.1")
	portscanCmd.Flags().StringVarP(&ps_port, "port", "p", config.Default_port, "Set `port` eg:1-1000,3306,3389 or use \" zscan ps -p l\" ) to scan less port（thirty port）")
	portscanCmd.Flags().BoolVar(&pingbefore, "noping", false, "not ping discovery before port scanning")
	portscanCmd.Flags().BoolVarP(&syn, "syn", "s",false, "use syn scan")
	portscanCmd.Flags().BoolVarP(&banner, "banner", "b",false, "Return banner information")
	portscanCmd.Flags().BoolVar(&webscan,"nowebscan",false,"Whether to perform HTTP scanning (httpTitle and HTTP vulnerabilities)(default on)")
	portscanCmd.Flags().BoolVar(&httpvulscan,"vulscan",false,"Whether to perform HTTP vulnerabilities(default off)")
	//portscanCmd.MarkFlagRequired("host")

}
