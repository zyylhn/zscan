package cmd

import (
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	AliveHosts []string
	OS         = runtime.GOOS
	ExistHosts = make(map[string]struct{})
	livewg     sync.WaitGroup
	scantype string
	useicmp bool
	discover string
)

var pingCmd = &cobra.Command{
	Use:              "ping",
	TraverseChildren: true,
	Short:            "ping scan to find computer",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result,Path_result)
		PrintScanBanner("ping")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		ping()
	},
}

func ping()  {
	switch discover {
	case "":
		GetHost()
		host,err:=Parse_IP(Hosts)
		Checkerr_exit(err)
		ICMPRun(host,!useicmp)
	case "local":
		localnet:=getlocalnet()
		ICMPRun(gettasklist(localnet),!useicmp)
	}

}

func ICMPRun(hostslist []net.IP, Ping bool) []string {
	Output("\n\r=========================living ip result list==========================\n",LightGreen)
	chanHosts := make(chan string, len(hostslist))
	go func() {
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
				ExistHosts[ip] = struct{}{}
				if Ping == false {
					Output(fmt.Sprintf("[%v] Find '%s' aliving\n", scantype,ip),White)
				} else {
					Output(fmt.Sprintf("[%v] Find '%s' aliving\n", scantype,ip),White)
				}
				AliveHosts = append(AliveHosts, ip)
			}
			livewg.Done()
		}
	}()

	if Ping {
		scantype="ping"
		RunPing(hostslist, chanHosts)
	} else {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			scantype="icmp listen"
			RunIcmp(hostslist, conn, chanHosts)
		}  else {
			Yellow("The current user permissions unable to send icmp packets\n")
			scantype="ping"
			RunPing(hostslist, chanHosts)
		}
	}

	livewg.Wait()
	close(chanHosts)
	Output(fmt.Sprintf("A total of %v IP addresses were discovered\n",len(AliveHosts)),LightGreen)
	return AliveHosts
}

func RunIcmp(hostslist []net.IP, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	for _, host := range hostslist {
		dst, _ := net.ResolveIPAddr("ip", host.String())
		IcmpByte := makemsg(host.String())
		conn.WriteTo(IcmpByte, dst)
	}
	start := time.Now()
	for {
		if len(AliveHosts) == len(hostslist) {
			break
		}
		since := time.Now().Sub(start)
		var wait time.Duration
		switch {
		case len(hostslist) <= 256:
			wait = time.Second * 5
		default:
			wait = time.Second * 10
		}
		if since > wait {
			break
		}
	}
	//fmt.Println(time.Now())
	endflag = true
	conn.Close()
}


func RunPing(hostslist []net.IP, chanHosts chan string) {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{},50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host, bsenv) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host.String())
	}
	wg.Wait()
}

func ExecCommandPing(ip string, bsenv string) bool {
	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}

func IsContain(items []net.IP, item string) bool {
	for _, eachItem := range items {
		if eachItem.String() == item {
			return true
		}
	}
	return false
}

func getlocalnet() []string {
	addr,err:=net.InterfaceAddrs()
	if err!=nil{
		fmt.Println(err)
	}
	localnet:=[]string{}
	for _,i :=range addr{
		if i.String()[0:3]=="172"{
			localnet=append(localnet,i.String()[0:7]+"0.0")
		}
		if i.String()[0:3]=="192"{
			localnet=append(localnet,i.String()[0:7]+"0.0")
		}
		if i.String()[0:3]=="10."{
			ip:=strings.Split(i.String(),".")
			localnet=append(localnet,ip[0]+"."+ip[1]+".0.0")
		}
	}
	localnet=RemoveRepByMap(localnet)
	return localnet
}

func gettasklist(network []string) []net.IP {
	var re []net.IP
	for _,i:=range network{
		for j:=0;j<256;j++{
			ip:=strings.Split(i,".")
			re=append(re,net.ParseIP(fmt.Sprintf("%v.%v.%v.%v",ip[0],ip[1],j,0)))
			re=append(re,net.ParseIP(fmt.Sprintf("%v.%v.%v.%v",ip[0],ip[1],j,1)))
			re=append(re,net.ParseIP(fmt.Sprintf("%v.%v.%v.%v",ip[0],ip[1],j,2)))
			re=append(re,net.ParseIP(fmt.Sprintf("%v.%v.%v.%v",ip[0],ip[1],j,255)))
		}
	}
	return re
}

//先进行ping扫描，将存活的ip以字符串
func ping_discover() string {
	host,err:=Parse_IP(Hosts)
	Checkerr_exit(err)
	return strings.Join(ICMPRun(host,!useicmp),",")
}

func init() {
	rootCmd.AddCommand(pingCmd)
	pingCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	pingCmd.Flags().BoolVarP(&useicmp,"icmp","i",false,"Icmp packets are sent to check whether the host is alive(need root)")
	pingCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap)")
	pingCmd.Flags().StringVarP(&discover, "discover", "d", "", "Live network segment found")
	//pingCmd.MarkFlagRequired("host")
}
