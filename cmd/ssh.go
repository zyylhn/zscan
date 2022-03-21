
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

var ssh_port int
var login_key bool
var key_path string


var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "burp ssh username password or traverse the key",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("ssh")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		Ssh()
	},
}

func Ssh()  {
	if login_key{
		if key_path==""{
			Output("must set private key",Red)
			return
		}else {
			burp_sshwithprivatekey()
		}
	}else {
		burp_ssh()
	}
}

func burp_ssh()  {
	GetHost()
	if Username==""{
		Username="root,admin,ssh"
	}
	burpthread=10
	ips:= Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{ssh_port},Connectssh,true)
	_=aliveserver.Run()
}

func burp_sshwithprivatekey()  {
	GetHost()
	if Username==""{
		Output("must set username ",Red)
		return
	}
	burpthread=10
	ips := Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{ssh_port},Connectssh,true)
	_=aliveserver.Run()
}


func Connectssh(ip string, port int) (string, int, error,[]string) {
	conn,err:=Getconn(ip,port)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("Start burp ssh : ",ip))
		_,f,_:=ssh_auto("root","Ksdvfjsxc",ip)
		if f{
			Output(fmt.Sprintf("%v Don't allow root login:%v \n","ssh",ip),LightGreen)
			var re []string
			if strings.Contains(Username,"root"){
				sl:=strings.Split(Username,",")
				for _,i:=range sl{
					if i=="root"{
						continue
					}
					re=append(re,i)
				}
				if !strings.Contains(Username,",")&&Username=="root"{
					Username=""
				}
			}
			Username=strings.Join(re,",")
		}
		if login_key{
			startburp:=NewBurp(key_path,Username,Userdict,Passdict,ip,ssh_auto_key,burpthread)
			startburp.Run()
		}else {
			startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,ssh_auto,burpthread)
			startburp.Run()
		}
	}
	return ip, port, err,nil
}

//爆破：返回是否连接成功
func ssh_auto( username, password,ip string) (error,bool,string) {
	success := false
	c,err:=ssh_connect_userpass(ip,username,password)
	if err==nil{
		c.Close()
		success=true
	}
	return err,success,"ssh"
}

func ssh_auto_key(user,keypath,ip string) (error,bool,string) {
	success := false
	//fmt.Println(Red(username,"\t",password,"\t",addr))
	c,err:=ssh_connect_publickeys(ip,user,keypath)
	if err==nil{
		defer c.Close()
		success=true
	}
	return err,success,"ssh"
}

//获取公钥认证Client
func ssh_connect_publickeys(ip,user,key_path string) (*ssh.Client, error) {
	var (
		err  error
		home_path string
		key []byte
	)
	switch  {
	case key_path=="":
		home_path, err= os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		key, err = ioutil.ReadFile(path.Join(home_path, ".ssh", "id_rsa"))
		if err != nil {
			return nil, err
		}
	case key_path!="":
		key, err = ioutil.ReadFile(key_path)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout:         Timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn,err:=Getconn(ip,ssh_port)
	Checkerr_exit(err)
	c,ch,re,err:=ssh.NewClientConn(conn,fmt.Sprintf("%v:%v",ip,ssh_port),clientConfig)
	if err !=nil{
		return nil,err
	}
	return ssh.NewClient(c,ch,re), nil
}

type sshclient struct {
	c ssh.Conn
	ch  <-chan ssh.NewChannel
	re <-chan *ssh.Request
	err error
}

//获取账号密码验证的Client
func ssh_connect_userpass(ip,user,pass string) (*ssh.Client,error) {
	client_config:=&ssh.ClientConfig{User: user,Auth: []ssh.AuthMethod{ssh.Password(pass)},HostKeyCallback: ssh.InsecureIgnoreHostKey(),Timeout: Timeout}
	conn,err:=Getconn(ip,ssh_port)
	if err!=nil{
		return nil,err
	}
	timeoutch:=make(chan sshclient)
	go func() {
		c1,ch1,re1,err1:=ssh.NewClientConn(conn,fmt.Sprintf("%v:%v",ip,ssh_port),client_config)
		timeoutch<-sshclient{c1,ch1,re1,err1}
	}()
	//c,ch,re,err:=ssh.NewClientConn(conn,addr,client_config)
	select{
	case sshclientdata:=<-timeoutch:
		if sshclientdata.err!=nil{
			return nil,sshclientdata.err
		}
		return ssh.NewClient(sshclientdata.c,sshclientdata.ch,sshclientdata.re),nil
	case <-time.After(Timeout):
		return nil,fmt.Errorf("不是ssh协议或者连接超时")
	}
	//if err !=nil{
	//	return nil,err
	//}
	//return ssh.NewClient(c,ch,re), nil
}

//利用Client进行交互式登陆
func ssh_login (client *ssh.Client)  {
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("new session error: %s", err.Error())
	}

	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err = session.RequestPty("xterm", 32, 160, modes); err != nil {
		log.Fatalf("request pty error: %s", err.Error())
	}
	if err = session.Shell(); err != nil {
		log.Fatalf("start shell error: %s", err.Error())
	}
	if err = session.Wait(); err != nil {
		log.Fatalf("return error: %s", err.Error())
	}
}

func init() {
	blastCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	sshCmd.Flags().StringVarP(&Hosts,"host","H","","Set ssh server host")
	sshCmd.Flags().IntVarP(&ssh_port,"port","p",22,"Set ssh server port")
	sshCmd.Flags().StringVarP(&Username,"username","U","","Set ssh username")
	sshCmd.Flags().StringVarP(&Password,"password","P","","Set ssh password")
	sshCmd.Flags().StringVarP(&Userdict,"userdict","","","Set ssh userdict path")
	sshCmd.Flags().StringVarP(&Passdict,"passdict","","","Set ssh passworddict path")
	sshCmd.Flags().BoolVarP(&login_key,"login_key","k",false,"Use public key login")
	sshCmd.Flags().StringVarP(&key_path,"keypath","d","","Set public key path")
	//sshCmd.MarkFlagRequired("host")
}
