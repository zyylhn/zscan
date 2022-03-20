package cmd

import (
	"embed"
	"fmt"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"zscan/cmd/web"
	lib "zscan/poccheck"
)
//go:embed pocs
var Pocs embed.FS
var TargetUrl string
var TargetFile string
var Pocpath string
var PocName string
var Listpoc bool
var PocThread int

var pocCmd = &cobra.Command{
	Use:   "poc",
	Short: "poc check",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("poc")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		execPoc()
	},
}

func execPoc()  {
	if Listpoc{
		lib.ListBuiltinPoc(Pocs,PocName)
		return
	}
	switch  {
	case TargetUrl!="":
		ExecSingleTarget(TargetUrl,Pocpath,PocName,PocThread)
	case TargetFile!="":
		ExecmultiTarget(TargetFile)
	default:
		fmt.Println(Red("Must set target \nadd --url/-u or --urlfile"))
		os.Exit(0)

	}
}

func ExecSingleTarget(target,pocpath,pocname string,pocthread int)  {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if pocpath==""{
		a:=lib.CheckBuiltinPoc(req, Pocs, pocthread, pocname)
		OutputVul(a)
	}else {
		if strings.HasSuffix(pocpath, ".yml") || strings.HasSuffix(pocpath, ".yaml"){
			lib.CheckSinglePoc(req,pocpath)
		}else {
			a:=lib.CheckExternalPoc(req,pocpath,pocthread,pocname)
			OutputVul(a)
		}
	}
}

func ExecmultiTarget(targetfile string)  {
	targetlist,err:=ReadFile(targetfile)
	wg:=sync.WaitGroup{}
	if err!=nil{
		Checkerr_exit(err)
	}
	tasklist:=make(chan string,Thread)
	for i:=0;i<Thread;i++{
		wg.Add(1)
		go func(wg *sync.WaitGroup,pocpath,pocname string,pocthread int) {
			for target:=range tasklist{
				ExecSingleTarget(target,pocpath,pocname,pocthread)
			}
			wg.Done()
		}(&wg,Pocpath,PocName,PocThread)
	}
	for _,i:=range targetlist{
		tasklist<-i
	}
	close(tasklist)
	wg.Wait()
}



func WebPocScan(url string,pocname string) *lib.PocResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	a:=lib.CheckBuiltinPoc(req, Pocs, PocThread, pocname)
	return a
}

func Selectpoc(name string) string {
	for _,i :=range web.PocDatas{
		if i.Name==name{
			return i.Alias
		}
	}
	return ""
}

func HttpVulScan(info *HostInfo)  {
	for _,i:=range info.Infostr{
		i=Selectpoc(i)   //将指纹信息换成对应的poc名字
		re:=WebPocScan(info.Url,i)        //poc扫描
		OutputVul(re)     //输出结果
		httpvul_result.Store(info.Url,re)   //存到全局
	}
}

func OutputVul(re *lib.PocResult)  {
	for _,i:=range re.Pocname{
		Output(fmt.Sprintf( "\r[+]Find vulnerability %s %s\n",re.Target,i),LightGreen)
	}
}

func init() {
	scanCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&TargetUrl,"url","u","","set target url")
	pocCmd.Flags().StringVar(&Pocpath,"pocpath","","set target url")
	pocCmd.Flags().StringVar(&PocName,"pocname","","set the poc name")
	pocCmd.Flags().BoolVarP(&Listpoc,"listpoc","l",false,"List built in poc")
	pocCmd.Flags().IntVar(&PocThread,"pocthread",359,"set poc scan thread")
	pocCmd.Flags().StringVar(&TargetFile,"urlfile","","set target file")
}
