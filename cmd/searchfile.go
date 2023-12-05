
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var rootdir string
var regular []string
var searchfielname []string
var regexes  []*regexp.Regexp
var walkNum int

var searchfileCmd = &cobra.Command{
	Use:   "searchfile",
	Short: "Search files that support regular matching",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintSearchFileBanner()
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		searchFile()
	},
}

func PrintSearchFileBanner()  {
	Output("\nMode:SearchFile\n",Red)
	Output(string(time.Now().AppendFormat([]byte("Start time:"), l1))+"\n",LightCyan)
	Output(fmt.Sprintf("Walk:%v\n",walkNum),LightCyan)
	Output(fmt.Sprintf("Filename:%v\n",searchfielname),LightCyan)
	Output(fmt.Sprintf("Regular:%v\n\n",regular),LightCyan)
}

func searchFile()  {
	if rootdir==""{
		fmt.Println(Red("Must set absolute path"))
		return
	}
	if regular==nil&&searchfielname==nil{
		fmt.Println(Red("Must set search file ues -f or -r"))
		return
	}
	GetRegexp()
	wg:=sync.WaitGroup{}
	walkFindfile(rootdir,walkFn,0,&wg)
	wg.Wait()
}

func GetRegexp()  {
	if searchfielname!=nil{
		for _,v:=range searchfielname{
			regexes=append(regexes, regexp.MustCompile(`^`+v+`$`))
		}
	}
	if regular!=nil{
		for _,v:=range regular{
			regexes=append(regexes,regexp.MustCompile(v))
		}
	}
}

func walkFn(path string, f os.FileInfo, err error) error {
	for _, r := range regexes {
		if r.MatchString(f.Name()) {
			Output(fmt.Sprintf("[+] Find--> Size:%v\tPath:%v\n",f.Size(),path),LightGreen)
		}
	}
	return nil
}

func walkFindfile(path string,fn filepath.WalkFunc,depth int,wg *sync.WaitGroup)  {
	files, err := ioutil.ReadDir(path)
	if err != nil{
		return
	}
	for _, file := range files{
		if file.IsDir(){
			if depth==walkNum{
				wg.Add(1)
				go findFile(filepath.Join(path,file.Name()),fn,wg)
				continue
			}else {
				walkFindfile(filepath.Join(path,file.Name()),fn, depth+1,wg)
				continue
			}
		}else{
			walkFn(filepath.Join(path,file.Name()),file,nil)
		}
	}
}

func findFile(path string,fn filepath.WalkFunc,wg *sync.WaitGroup)  {
	defer wg.Done()
	filepath.Walk(path, fn)
}

func init() {
	toolsCmd.AddCommand(searchfileCmd)
	searchfileCmd.Flags().StringArrayVarP(&regular,"regexp","r",nil,"Specifies the re matching parameters")
	searchfileCmd.Flags().StringArrayVarP(&searchfielname,"file","f",nil,"set filename eg:appname tools searchfile -d ./ -f pass.txt -f user.txt")
	searchfileCmd.Flags().StringVarP(&rootdir,"dir","d","","set search base Dir")
	searchfileCmd.Flags().IntVar(&walkNum,"walk",3,"Traversal turns on multithreading depth(Try not to go above 5)")
}
