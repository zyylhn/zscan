package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"sort"
	"sync"
	"time"
)

var httptitle_result sync.Map
var pingbefore bool
var banner bool
var ps_port string
var portscanCmd = &cobra.Command{
	Use:   "ps",
	Short: "Port Scan",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result,Path_result)
		PrintScanBanner("ps")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		GetHost()
		if pingbefore {
			Hosts = ping_discover()
		}
		ips, err := Parse_IP(Hosts)
		Checkerr(err)
		ports, err := Parse_Port(ps_port)
		Checkerr(err)
		portscan(ips,ports)
	},
}


func portscan(ips []net.IP,ports []int)  {
	var port_scan *PortScan
	if banner{
		port_scan=NewPortScan(ips,ports,Connect_BannerScan)
	}else {
		port_scan=NewPortScan(ips,ports,Connect)
	}
	r:=port_scan.Run()
	getHttptitle(r)
	Printresult(r)

}

type Openport struct {
	ip string   //ip地址
	port []int   //所有开启的端口
	banner map[int][]string  //端口号为key的banner信息
}


type PortScan struct {
	iplist []net.IP
	ports []int
	wg sync.WaitGroup
	taskch chan map[string]int
	resultch chan []string
	tcpconn Connect_method
	result map[string]*Openport
	portscan_result sync.Map
	tasknum float64
	donenum float64

}

func NewPortScan(iplist []net.IP,ports []int,connect Connect_method) *PortScan {
	return &PortScan{iplist: iplist,ports: ports,taskch: make(chan map[string]int,Thread*2),tcpconn: connect,resultch: make(chan []string,Thread*2),result: make(map[string]*Openport),tasknum: float64(len(iplist)*len(ports))}
}

//端口扫描的开始函数，返回结果
func (p *PortScan) Run() map[string]*Openport {
	go p.Gettasklist()
	for i := 0; i < Thread; i++ {
		go p.Startscan()
	}
	go p.bar()
	time.Sleep(time.Second)  //防止线程开的太低就运行到Wait
	p.wg.Wait()
	p.Getresult()
	return p.result
}

//获取任务列表
func (p *PortScan) Gettasklist()  {
	p.wg.Add(1)
	defer p.wg.Done()
	for _, port := range p.ports  {
		for _, ip := range p.iplist  {
			//fmt.Println(ip)
			ipPort := map[string]int{ip.String(): port}
			//fmt.Println(ipPort)
			p.taskch <- ipPort
		}
	}
	close(p.taskch)
}

//扫描函数
func (p *PortScan) Startscan()  {
	p.wg.Add(1)
	defer p.wg.Done()
	for task := range p.taskch {
		for ip, port := range task {
			//fmt.Println(ip,port)
			err := p.Saveresult(p.tcpconn(ip, port))
			p.donenum+=1
			_ = err //dial tcp 172.16.95.1:3301: connect: connection refused
		}
	}
}

//将结果保存下来
func (p *PortScan) Saveresult(ip string, port int, err error,banner []string) error {
	if err != nil {
		return err
	}
	v, ok := p.portscan_result.Load(ip)
	if ok {
		ports, ok1 := v.(map[int][]string)
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
			fmt.Printf("\r%c ps:%4.2f%v %c", r,float64(p.donenum/p.tasknum*100),"%",r)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

//格式化输出ps模块的结果
func Printresult(r map[string]*Openport)  {
	Output("\n\r============================port result list=============================\n",LightGreen)
	Output(fmt.Sprintf("There are %v IP addresses in total\n",len(r)),LightGreen)
	realIPs := make([]net.IP, 0, len(r))
	for ip,_:=range r{
		realIPs = append(realIPs, net.ParseIP(ip))
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
	Output("============================http result list=============================\n",LightGreen)
	httptitle_result.Range(func(key, value interface{}) bool {
		Output(fmt.Sprintf("Traget:%v\n", key),LightBlue)
		Output(fmt.Sprintf("%v\n", value),White)
		return true
	})
}


func getHttptitle(r map[string]*Openport)  {
	wg:=sync.WaitGroup{}
	httptask:=make(chan string,Thread)
	for i:=0;i<Thread;i++{
		go func() {
			wg.Add(1)
			defer wg.Done()
			for task:=range httptask{
				getScanTitl(task)
			}
		}()
	}
	for _,i:=range r{
		for _,port:=range i.port{
			t:=fmt.Sprintf("%v:%v",i.ip,port)
			httptask<-t
		}
	}
	close(httptask)
	wg.Wait()
}

func init() {
	rootCmd.AddCommand(portscanCmd)
	portscanCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	portscanCmd.Flags().BoolVarP(&useicmp,"icmp","i",false,"Icmp packets are sent to check whether the host is alive(need root)")
	portscanCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap) eg:192.168.1.1/24,172.16.95.1-100,127.0.0.1")
	portscanCmd.Flags().StringVarP(&ps_port, "port", "p", default_port, "Set `port` eg:1-1000,3306,3389")
	portscanCmd.Flags().BoolVar(&pingbefore, "ping", false, "Ping host discovery before port scanning")
	portscanCmd.Flags().BoolVarP(&banner, "banner", "b",false, "Return banner information")
	//portscanCmd.MarkFlagRequired("host")
}
