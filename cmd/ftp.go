package cmd

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/spf13/cobra"
	"time"
)

var ftp_port int

var ftpCmd = &cobra.Command{
	Use:   "ftp",
	Short: "burp ftp username and password ",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result,Path_result)
		PrintScanBanner("ftp")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		ftpscan()
	},
}

func ftpscan()  {
	burp_ftp()
}

func burp_ftp()  {
	GetHost()
	if Command!=""{
		err,_,_:=ftp_auth(Username,Password,Hosts)
		if err!=nil{
			fmt.Println(err)
		}
		return
	}
	if Username==""{
		Username="ftp,anonymous,root"
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{ftp_port},Connectftp,true)
	_=aliveserver.Run()
}

func Connectftp(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn(fmt.Sprintf("%s:%d", ip, ftp_port))
	defer func() {
		if conn != nil {
			_ = conn.Close()
			fmt.Printf(White(fmt.Sprintf("\r[*]Find port %v:%v\r\n", ip, port)))
			fmt.Println(Yellow("Start burp ftp : ",ip))
			startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,ftp_auth,burpthread)
			startburp.Run()
		}
	}()
	return ip, port, err,nil
}

func ftp_auth(username,password,ip string) (error,bool,string) {
	c,err:=Getconn(fmt.Sprintf("%s:%d", ip, ftp_port))
	if err!=nil{
		return err,false,"ftp"
	}
	conn, err := ftp.Dial(fmt.Sprintf("%s:%d", ip, ftp_port), ftp.DialWithNetConn(c))
	if err == nil {
		err = conn.Login(username, password)
		if err == nil {
			if Command != "" {
				output, err := FTPExec(conn)
				if err == nil {
					fmt.Println(output)
				}
			}
			return err,true,"ftp"
		}
		return err,false,"ftp"
	}
	return err,false,"ftp"
}

func FTPExec(client *ftp.ServerConn) (string, error) {

	fileList, err := client.List("")
	if err != nil {
		return "", err
	}

	defer client.Logout()
	defer client.Quit()

	var s string
	for _, file := range fileList {
		var fileType string
		if file.Type == 1 {
			fileType = "directory"
		} else {
			fileType = "file"
		}
		s += fmt.Sprintf("%-30s %-9s %-8d %s\n", file.Name, fileType, file.Size, file.Time.Format("2006-01-02T15:04:05.999999"))
	}

	return s, nil
}


func init() {
	rootCmd.AddCommand(ftpCmd)
	ftpCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	ftpCmd.Flags().StringVarP(&Hosts,"host","H","","Set ftp server host")
	ftpCmd.Flags().IntVarP(&ftp_port,"port","p",21,"Set ftp server port")
	ftpCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	ftpCmd.Flags().StringVarP(&Username,"username","U","","Set ftp username")
	ftpCmd.Flags().StringVarP(&Command,"command","c","","Set the command you want to execute")
	ftpCmd.Flags().StringVarP(&Password,"password","P","","Set ftp password")
	ftpCmd.Flags().StringVarP(&Userdict,"userdict","","","Set ftp userdict path")
	ftpCmd.Flags().StringVarP(&Passdict,"passdict","","","Set ftp passworddict path")
	//ftpCmd.MarkFlagRequired("host")

}
