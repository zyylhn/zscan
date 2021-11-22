package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

func ScanTitle(host string) string {
	url := "http://" + host
	html, code := GetHtml(url)
	title := GetTitle(html)
	if code!=0 {
		return fmt.Sprintf("Url:%v\tCode:%v\tTitle:%v\n", url, code, title)
	}
	url = "https://" + host
	html, code = GetHtml(url)
	title = GetTitle(html)
	if code!=0{
		return fmt.Sprintf("Url:%v\tCode:%v\tTitle:%v\n", url, code, title)
	}
	return ""
}

func GetTitle(html string) string {
	re, _ := regexp.Compile("\\<[\\S\\s]+?\\>")
	html = re.ReplaceAllStringFunc(html, strings.ToLower)
	html = strings.Replace(html, "\n", "", -1)
	title := strings.Trim(GetBetween(html, "<title>", "</title>"), " ")
	return title
}

func GetHtml(url string) (string, int) {
	client := &http.Client{Timeout: Timeout*3}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	var buffer [512]byte
	result := bytes.NewBuffer(nil)
	for {
		n, err := resp.Body.Read(buffer[0:])
		result.Write(buffer[0:n])
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return "", 0
		}
	}
	return result.String(), resp.StatusCode
}

//获取title
func getScanTitl(ipport string) {
	//url := ip + ":" + strconv.FormatInt(int64(port), 10)
	if title := ScanTitle(ipport); title != "" {
		httptitle_result.Store(ipport, title)
	}
}