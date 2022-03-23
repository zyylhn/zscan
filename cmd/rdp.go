package cmd

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)
var rdpburpthread int
var rdp_port int
var rdpCmd = &cobra.Command{
	Use:   "rdp",
	Short: "burp remote desktop（3389）",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("rdp")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		rdpmode()
	},
}

func rdpmode()  {
	burp_rdp()
}

func burp_rdp()  {
	GetHost()
	if Username==""{
		Username="Administrator,admin"
	}
	ips := Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{rdp_port},Connectrdp,true)
	_=aliveserver.Run()
}

func Connectrdp(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn( ip, port)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("\rStart burp rdp : ",ip))
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,rdp_auth,rdpburpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func rdp_auth(username,password,ip string) (error,bool,string) {
	//target := fmt.Sprintf("%s:%d", ip, rdp_port)
	g := NewClient(ip, glog.NONE)
	domain,user:=getusername(username)
	err := g.Login(domain, user, password)
	if err == nil {
		return nil,true,"rdp"
	}
	return err,false,"rdp"
}

//拆分域名和用户名
func getusername(username string) (string,string) {
	if a:=strings.Split(username,"/");len(a)==2{
		return a[0],a[1]
	}else {
		return "",username
	}
}

type Rdpclient struct {
	Host string // ip
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

func NewClient(host string, logLevel glog.LEVEL) *Rdpclient {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Rdpclient{
		Host: host,
	}
}

func (g *Rdpclient) Login(domain, user, pwd string) error {
	conn, err := Getconn(g.Host,rdp_port)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	//g.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)
	//g.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")
	wg := &sync.WaitGroup{}
	breakFlag := false
	wg.Add(1)

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		err = nil
		glog.Info("on success")
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
		g.pdu.Emit("done")
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
	})
	g.pdu.On("done", func() {
		if breakFlag == false {
			breakFlag = true
			wg.Done()
		}
	})

	wg.Wait()
	return err
}


func init() {
	blastCmd.AddCommand(rdpCmd)
	rdpCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	rdpCmd.Flags().StringVarP(&Hosts,"host","H","","Set rdp server host")
	rdpCmd.Flags().IntVarP(&rdp_port,"port","p",3389,"Set rdp server port")
	rdpCmd.Flags().IntVarP(&rdpburpthread,"burpthread","",50,"Set burp password thread(recommend not to change)")
	rdpCmd.Flags().StringVarP(&Username,"username","U","","Set rdp username eg:admin,domain/administrator")
	rdpCmd.Flags().StringVarP(&Password,"password","P","","Set rdp password")
	rdpCmd.Flags().StringVarP(&Userdict,"userdict","","","Set rdp userdict path")
	rdpCmd.Flags().StringVarP(&Passdict,"passdict","","","Set rdp passworddict path")
}
