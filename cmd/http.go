package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"zscan/cmd/web"
)

var (
	Charsets = []string{"utf-8", "gbk", "gb2312"}
)

type httpresp struct {
	len string
	title string
	code int
}

type HostInfo struct {
	Host      string
	Ports     string
	Url       string
	Timeout   time.Duration
	Infostr   []string
	baseinfo *httpresp
}



//flag 1 first try
//flag 2 /favicon.ico
//flag 3 302
//flag 4 400 -> https
//根据协议设置url，进行第一次获取checkdata尝试，如果遇到跳转则跟进再次尝试，如果返回有https则重新设置url再次尝试以上步骤
func WebTitle(info *HostInfo) (*HostInfo,error) {
	var CheckData []web.CheckDatas
	//设置url
	if info.Url == "" {
		if info.Ports == "80" {
			info.Url = fmt.Sprintf("http://%s", info.Host)
		} else if info.Ports == "443" {
			info.Url = fmt.Sprintf("https://%s", info.Host)
		} else {
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, info.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			protocol := GetProtocol(info.Url, info.Timeout)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}
	//re返回跳转的url或者https，checkdata是header和body
	err, result, CheckData := geturl(info, 1, CheckData)
	//fmt.Println("第一次",result,string(CheckData[0].Body))
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return nil,err
	}

	//判断是否有跳转,如果有跳转，跟进跳到头，增加一次的CheckData
	if strings.Contains(result, "://") {
		redirecturl, err := url.Parse(result)
		if err == nil {
			info.Url = redirecturl.String()
			err, result, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return nil,err
			}
		}
	}
	//判断返回如果是https
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, 1, CheckData)
		if strings.Contains(result, "://") {
			//有跳转
			redirecturl, err := url.Parse(result)
			if err == nil {
				info.Url = redirecturl.String()
				err, result, CheckData = geturl(info, 3, CheckData)
				if err != nil {
					return nil,err
				}
			}
		} else {
			if err != nil {
				return nil,err
			}
		}
	} else if err != nil {
		return nil,err
	}

	err, _, CheckData = geturl(info, 2, CheckData)
	if err != nil {
		return nil,err
	}
	//将CheckData送去与指纹库对比
	info.Infostr = web.InfoCheck(CheckData)
	OutputHttp(info)   //扫描过程中输出titl信息
	httptitle_result.Store(fmt.Sprintf("%v:%v",info.Host,info.Ports), info)
	return info,err
}

func geturl(info *HostInfo, flag int, CheckData []web.CheckDatas) (error, string, []web.CheckDatas) {
	Url := info.Url
	//fmt.Println(Url)
	//设置url：访问到网站的图标
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}

	req, err := http.NewRequest("GET", Url, nil)
	if err == nil {
		//设置http请求头，并在cookie后面添加shior识别
		req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		//if common.PocInfo.!= "" {
		//	req.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
		//} else {
		req.Header.Set("Cookie", "rememberMe=1")
		//}
		req.Header.Set("Connection", "close")

		var client *http.Client
		if flag == 1 {
			client = ClientNoRedirect
		} else {
			client = Client
		}
		//发送请求
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var title string
			var text []byte
			body, err := getRespBody(resp)
			//fmt.Println(string(body))
			if err != nil {
				//fmt.Println(err)
				return err, "https", CheckData
			}
			//获取http title
			if flag != 2 {
				//获取title
				re := regexp.MustCompile("(?ims)<title.*>(.*)</title>")
				//fmt.Println(string(body))
				find := re.FindSubmatch(body)
				//fmt.Println("正则匹配到",string(find[0]),"\n",string(find[0]))
				//fmt.Println(find)
				if len(find) > 1 {
					text = find[1]
					GetEncoding := func() string { // 判断Content-Type
						r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
						if err != nil {
							return ""
						}
						headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
						if headerCharset != "" {
							for _, v := range Charsets { // headers 编码优先，所以放在前面
								if strings.Contains(strings.ToLower(headerCharset), v) == true {
									return v
								}
							}
						}

						r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
						if err != nil {
							return ""
						}
						htmlCharset := r2.FindString(string(body))
						if htmlCharset != "" {
							for _, v := range Charsets {
								if strings.Contains(strings.ToLower(htmlCharset), v) == true {
									return v
								}
							}
						}
						return ""
					}
					encode := GetEncoding()
					//_, encode1, _ := charset.DetermineEncoding(body, "")
					var encode2 string
					detector := chardet.NewTextDetector()
					detectorstr, _ := detector.DetectBest(body)
					if detectorstr != nil {
						encode2 = detectorstr.Charset
					}
					if encode == "gbk" || encode == "gb2312" || strings.Contains(strings.ToLower(encode2), "gb") {
						titleGBK, err := Decodegbk(text)
						if err == nil {
							title = string(titleGBK)
						}
					} else {
						title = string(text)
					}
				} else {
					title = ""
				}
				title = strings.Trim(title, "\r\n \t")
				title = strings.Replace(title, "\n", "", -1)
				title = strings.Replace(title, "\r", "", -1)
				title = strings.Replace(title, "&nbsp;", " ", -1)
				if len(title) > 100 {
					title = title[:100]
				}
				if title == "" {
					title = ""
				}
				length := resp.Header.Get("Content-Length")
				if length == "" {
					length = fmt.Sprintf("%v", len(body))
				}
				//result := fmt.Sprintf("[*] WebTitle:%-25v code:%-3v len:%-6v title:%v", resp.Request.URL, resp.StatusCode, length, title)
				info.baseinfo=&httpresp{title: title,code: resp.StatusCode,len: length}
			}
			CheckData = append(CheckData, web.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
			redirURL, err1 := resp.Location()
			if err1 == nil {
				return nil, redirURL.String(), CheckData
			}
			if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
				return err, "https", CheckData
			}
			return nil, "", CheckData
		}
		return err, "https", CheckData
	}
	return err, "", CheckData
}

func Decodegbk(s []byte) ([]byte, error) { // GBK解码
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

//获取响应body
func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

//判断是什么协议
func GetProtocol(host string, Timeout time.Duration) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: Timeout}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	protocol := "http"
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	keepAlive        = 15 * time.Second
)

func Inithttp() {
	err := InitHttpClient(Thread, Timeout)
	if err != nil {
		log.Fatal(err)
	}
}

func InitHttpClient(ThreadsNum int,Timeout time.Duration) error {
	//dialer := &net.Dialer{
	//	Timeout:   dialTimout,
	//	KeepAlive: keepAlive,
	//
	//}
	d:= func(ctx context.Context,network,addr string)(net.Conn,error) {
		return Getconn(addr)
	}
	tr := &http.Transport{
		DialContext:         d,
		MaxConnsPerHost:     0,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: Timeout*2,
		DisableKeepAlives:   false,
	}
	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout*3,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout*3,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

func OutputHttp(v *HostInfo)  {
	Output("\r"+v.Url,White)
	if v.baseinfo.code==200{
		Output(fmt.Sprintf("  code:",),White)
		Output(fmt.Sprintf("%v",v.baseinfo.code),LightGreen)
	}else {
		Output(fmt.Sprintf("  code:",),White)
		Output(fmt.Sprintf("%v",v.baseinfo.code),Yellow)
	}
	Output(fmt.Sprintf("  len:%v",v.baseinfo.len),White)
	Output(fmt.Sprintf("  title:"),White)
	Output(fmt.Sprintf("%v",v.baseinfo.title),LightGreen)
	Output(fmt.Sprintf("  banner:"),White)
	for _,i:=range v.Infostr{
		Output(fmt.Sprintf("%v",i),LightGreen)
	}
	Output("\n",White)
}
