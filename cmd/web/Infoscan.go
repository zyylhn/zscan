package web

import (
	"crypto/md5"
	"fmt"
	"github.com/gookit/color"
	"regexp"

)
var LightGreen = color.FgLightGreen.Render

type CheckDatas struct {
	Body    []byte
	Headers string
}

func InfoCheck(Url string, CheckData []CheckDatas) []string {
	var matched bool
	var infoname []string
	//遍历checkdata和rule
	for _, data := range CheckData {
		for _, rule := range RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
				//infoname = append(infoname, rule.Rule)
			}
		}
		flag, name := CalcMd5(data.Body)
		if flag == true {
			infoname = append(infoname, name)
			//infoname = append(infoname, name)
		}
	}

	infoname = removeDuplicateElement(infoname)

	if len(infoname) > 0 {
		result := fmt.Sprintf("\r[*]Find http banner:%-25v %s \r", Url, infoname)
		fmt.Println(LightGreen(result))
		return infoname
	}
	return []string{""}
}

func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
