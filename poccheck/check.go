package lib

import (
	"embed"
	"fmt"
	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ceyeApi    = "a78a1cb49d91fe09e01876078d1868b2"
	ceyeDomain = "7wtusr.ceye.io"
)

type Task struct {
	Req *http.Request
	Poc *Poc
}

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
)

var mutex sync.Mutex

func Inithttp(client,clientnoredirect *http.Client)  {
	Client=client
	ClientNoRedirect=clientnoredirect
}

type PocResult struct {
	Target string
	Pocname []string
}

//并发执行内置poc
func CheckBuiltinPoc(req *http.Request, Pocs embed.FS, workers int, pocname string) *PocResult {
	var result PocResult
	result.Target=req.URL.String()
	tasks := make(chan Task)    //poc任务列表
	var wg sync.WaitGroup
	wg.Add(1)
	go getPocTaskList(Pocs,pocname,req,tasks,&wg)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go runPocExec(tasks,&wg,&result.Pocname)
	}
	wg.Wait()
	return &result
}

//并发执行外部poc
func CheckExternalPoc(req *http.Request,pocdir string,workers int,pocname string) *PocResult {
	var result PocResult
	result.Target=req.URL.String()
	tasks := make(chan Task)
	var wg sync.WaitGroup
	wg.Add(1)
	go getPocTaskListfile(pocdir,pocname,req,tasks,&wg)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go runPocExec(tasks,&wg,&result.Pocname)
	}
	wg.Wait()
	return &result
}

//直接执行单个poc
func CheckSinglePoc(req *http.Request,pocpath string) *PocResult {
	var result PocResult
	result.Target=req.URL.String()
	poc,err:=loadExternalPoc(pocpath)
	if err!=nil{
		fmt.Println(err)
		return nil
	}
	isVul, _ ,_:= executePoc(req, poc)
	if isVul {
		//result := fmt.Sprintf("[+]Find vulnerability %s %s %s", req.URL, poc.Name,name)
		result.Pocname=append(result.Pocname,poc.Name)
	}
	return &result
}

func executePoc(oReq *http.Request, p *Poc) (bool, error,string) {
	c := NewEnvOption()   //创建CustomLib对象（用于创建环境）
	c.UpdateCompileOptions(p.Set)  //将set中的变量添加到环境中
	if len(p.Sets) > 0 {       //用来检测弱口令
		setMap := make(map[string]string)     //但是只能遍历到列表的第一个（?）
		for k := range p.Sets {
			setMap[k] = p.Sets[k][0]
		}
		c.UpdateCompileOptions(setMap)
	}
	env, err := NewEnv(&c)
	if err != nil {
		fmt.Printf("[-] %s environment creation error: %s\n",p.Name,err)
		return false, err, ""
	}
	req, err := ParseRequest(oReq)  //将oReq转换成我们自己定义的request（？）
	if err != nil {
		fmt.Printf("[-] %s ParseRequest error: %s\n",p.Name,err)
		return false, err, ""
	}
	variableMap := make(map[string]interface{})     //执行表达式要传进去的参数（按照xray的变量定义）
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	keys := make([]string, 0)
	keys1 := make([]string, 0)
	for k := range p.Set {
		if strings.Contains(strings.ToLower(p.Set[k]), "random") && strings.Contains(strings.ToLower(p.Set[k]), "(") {
			keys = append(keys, k) //优先放入调用random系列函数的变量
		} else {
			keys1 = append(keys1, k)
		}
	}
	sort.Strings(keys)
	sort.Strings(keys1)
	keys = append(keys, keys1...)
	for _, k := range keys {
		expression := p.Set[k]
		if k != "payload" {
			if expression == "newReverse()" {
				variableMap[k] = newReverse()
				continue
			}
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				//fmt.Println(p.Name,"  poc_expression error",err)
				variableMap[k] = expression
				continue
			}
			switch value := out.Value().(type) {
			case *UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			case []uint8:
				variableMap[k] = fmt.Sprintf("%s", out)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	if p.Set["payload"] != "" {
		out, err := Evaluate(env, p.Set["payload"], variableMap)
		if err != nil {
			//fmt.Println(p.Name,"  poc_payload error",err)
			return false, err, ""
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	setslen := 0
	haspayload := false
	var setskeys []string
	if len(p.Sets) > 0 {
		for _, rule := range p.Rules {
			for k := range p.Sets {
				if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						haspayload = true
					}
					setslen++
					setskeys = append(setskeys, k)
					continue
				}
				for k2 := range rule.Headers {
					if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
						if strings.Contains(k, "payload") {
							haspayload = true
						}
						setslen++
						setskeys = append(setskeys, k)
						continue
					}
				}
			}
		}
	}

	success := false
	//爆破模式,比如tomcat弱口令
	if setslen > 0 {
		if haspayload {
			success, err = clusterpoc1(oReq, p, variableMap, req, env, setskeys)
		} else {
			success, err = clusterpoc(oReq, p, variableMap, req, env, setslen, setskeys)
		}
		return success, nil, ""
	}


	DealWithRule := func(rule Rules) (bool, error) {
		var (
			flag, ok bool
		)
			for k1, v1 := range variableMap {
				_, isMap := v1.(map[string]string)
				if isMap {
					continue
				}
				value := fmt.Sprintf("%v", v1)
				for k2, v2 := range rule.Headers {
					rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
				}
				rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
				rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
			}

			if oReq.URL.Path != "" && oReq.URL.Path != "/" {
				req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
			} else {
				req.Url.Path = rule.Path
			}
			// 某些poc没有区分path和query，需要处理
			req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
			req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

			newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
			newRequest.Header = oReq.Header.Clone()
			for k, v := range rule.Headers {
				newRequest.Header.Set(k, v)
			}

			resp, err := DoRequest(newRequest, rule.FollowRedirects)
			if err != nil {
				return false, err
			}
			variableMap["response"] = resp
			// 先判断响应页面是否匹配search规则
			if rule.Search != "" {
				result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
				if result != nil && len(result) > 0 { // 正则匹配成功
					for k, v := range result {
						variableMap[k] = v
					}
				} else {
					return false, nil
				}
			}
			out, err := Evaluate(env, rule.Expression, variableMap)
			if err != nil {
				return false, err
			}
			//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
			//如果false不继续执行后续rule
			// 如果最后一步执行失败，就算前面成功了最终依旧是失败
			flag, ok = out.Value().(bool)
			if !ok {
				flag = false
			}
			return flag, nil
	}

	DealWithRules := func(rules []Rules) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)
			//if err != nil {
			//	fmt.Printf("[-] %s Execute Rule error: %s\n",p.Name,err.Error())
			//}

			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
		}
		return successFlag
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else { // Groups
		for name, rules := range p.Groups {
			success = DealWithRules(rules)
			if success {
				return success, nil, name
			}
		}
	}

	return success, nil, ""
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := RandomStr(randSource, letters, 8)
	if true {
		//默认不开启dns解析
		return &Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, slen int, keys []string) (success bool, err error) {
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		n := 0
		for k := range p.Sets {
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					n++
					continue
				}
			}
		}
		if n == 0 {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}

		if slen == 1 {
		look1:
			for _, var1 := range p.Sets[keys[0]] {
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
				success, err = clustersend(oReq, variableMap, req, env, rule1)
				if err != nil {
					return false, err
				}
				if success == true {
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if slen == 2 {
		look2:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
					success, err = clustersend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if slen == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						success, err = clustersend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func clusterpoc1(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, keys []string) (success bool, err error) {
	setMap := make(map[string]interface{})
	for k := range p.Sets {
		setMap[k] = p.Sets[k][0]
	}
	setMapbak := cloneMap1(setMap)
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		varset := []string{}
		varpay := []string{}
		n := 0
		for k := range p.Sets {
			// 1. 如果rule中需要修改 {{k}} 如username、payload
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				if strings.Contains(k, "payload") {
					varpay = append(varpay, k)
				} else {
					varset = append(varset, k)
				}
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						varpay = append(varpay, k)
					} else {
						varset = append(varset, k)
					}
					n++
					continue
				}
			}
		}

		for _, key := range varpay {
			v := fmt.Sprintf("%s", setMap[key])
			for k := range p.Sets {
				if strings.Contains(v, k) {
					if !IsContain(varset, k) && !IsContain(varpay, k) {
						varset = append(varset, k)
					}
				}
			}
		}
		if n == 0 {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}
		if len(varset) == 1 {
		look1:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varset[0]] {
				setMap := cloneMap1(setMapbak)
				setMap[varset[0]] = var1
				evalset(env, setMap)
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varset[0]+"}}", var1)
					for _, key := range varpay {
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[0]+"}}", var1)
				for _, key := range varpay {
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
				}
				success, err = clustersend(oReq, variableMap, req, env, rule)
				if err != nil {
					return false, err
				}

				if success == true {
					fmt.Printf("[+] %s://%s%s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, var1)
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if len(varset) == 2 {
		look2:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varset[0]] { //username
				for _, var2 := range p.Sets[varset[1]] { //password
					setMap := cloneMap1(setMapbak)
					setMap[varset[0]] = var1
					setMap[varset[1]] = var2
					evalset(env, setMap)
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varset[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+varset[1]+"}}", var2)
						for _, key := range varpay {
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[1]+"}}", var2)
					for _, key := range varpay {
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
					success, err = clustersend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						fmt.Printf("[+] %s://%s%s %s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, var1, var2)
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if len(varset) == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						setMap := cloneMap1(setMapbak)
						setMap[varset[0]] = var1
						setMap[varset[1]] = var2
						evalset(env, setMap)
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
							for _, key := range varpay {
								rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							}
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						for _, key := range varpay {
							rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
						success, err = clustersend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules) (bool, error) {
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}
	// 某些poc没有区分path和query，需要处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
	req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

	newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	resp, err := DoRequest(newRequest, rule.FollowRedirects)
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// 先判断响应页面是否匹配search规则
	if rule.Search != "" {
		result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
		if result != nil && len(result) > 0 { // 正则匹配成功
			for k, v := range result {
				variableMap[k] = v
			}
			//return false, nil
		} else {
			return false, nil
		}
	}

	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		return false, err
	}
	//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
	if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
		return false, err // 如果最后一步执行失败，就算前面成功了最终依旧是失败
	}
	return true, err
}

func cloneRules(tags Rules) Rules {
	cloneTags := Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func cloneMap1(tags map[string]interface{}) map[string]interface{} {
	cloneTags := make(map[string]interface{})
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func evalset(env *cel.Env, variableMap map[string]interface{}) {
	for k := range variableMap {
		expression := fmt.Sprintf("%v", variableMap[k])
		if !strings.Contains(k, "payload") {
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				//fmt.Println(err)
				variableMap[k] = expression
				continue
			}
			switch value := out.Value().(type) {
			case *UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = fmt.Sprintf("%v", value)
			case []uint8:
				variableMap[k] = fmt.Sprintf("%v", out)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	for k := range variableMap {
		expression := fmt.Sprintf("%v", variableMap[k])
		if strings.Contains(k, "payload") {
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				//fmt.Println(err)
				variableMap[k] = expression
			} else {
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}
}

func LoadBuiltinPoc(Pocs embed.FS, pocname string) []*Poc {
	var pocs []*Poc
	for _, f := range SelectBuiltinPoc(Pocs, pocname) {
		if p, err := loadBuiltinPoc(f, Pocs); err == nil {
			pocs = append(pocs, p)
		}else {
			fmt.Println("[-] load poc ",f," error:",err)
		}
	}
	return pocs
}

//将一个poc文件转换成Poc对象
func loadBuiltinPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		return nil, err
	}
	return p, err
}

//根据pocname选择poc
func SelectBuiltinPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		fmt.Println(err)
	}
	var foundFiles []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), pocname) {
			foundFiles = append(foundFiles, entry.Name())
		}
	}
	return foundFiles
}

//列出内置所有可用的poc，可根据pocname筛选
func ListBuiltinPoc(Pocs embed.FS,pocname string)  {
	pocs:=SelectBuiltinPoc(Pocs,pocname)
	for _,p:=range pocs{
		fmt.Println(p)
	}
}

func LoadExternalPoc(pocdir ,pocname string) []*Poc {
	pocdir = strings.ReplaceAll(pocdir, "\\", "/")
	var pocs []*Poc
	for _, filename := range selectExternalPoc(pocdir,pocname) {
		if p, err := loadExternalPoc(filename); err == nil {
			pocs = append(pocs, p)
		}
	}
	return pocs
}

func loadExternalPoc(fileName string) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		return nil, err
	}
	return p, err
}

func selectExternalPoc(pocdir ,pocname string) []string {
	var foundFiles []string
	files,err:=ioutil.ReadDir(pocdir)
	if err!=nil{
		fmt.Println(err)
		return nil
	}
	for _,file:=range files{
		filename:=file.Name()
		if strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml") {
			if strings.Contains(filename, pocname) {
				foundFiles = append(foundFiles, pocdir+"/"+filename)
			}
		}
	}

	return foundFiles
}

func getPocTaskListfile(pocdir string,pocname string,req *http.Request,tasks chan Task,wg *sync.WaitGroup)  {
	defer wg.Done()
	for _,poc:=range LoadExternalPoc(pocdir,pocname){
		task := Task{
			Req: req,
			Poc: poc,
		}
		tasks <- task
	}
	close(tasks)
}

func getPocTaskList(Pocs embed.FS,pocname string,req *http.Request,tasks chan Task,wg *sync.WaitGroup)  {
	defer wg.Done()
	for _, poc := range LoadBuiltinPoc(Pocs, pocname) {   //根据poc名字返回对应的poc
		task := Task{
			Req: req,
			Poc: poc,
		}
		tasks <- task
	}
	close(tasks)
}

func runPocExec(tasks chan Task,wg *sync.WaitGroup,resultlist *[]string)  {
	defer wg.Done()
	for task := range tasks {
		isVul, _ ,_:= executePoc(task.Req, task.Poc)
		if isVul {
			//result := fmt.Sprintf("[+]Find vulnerability %s %s %s", task.Req.URL, task.Poc.Name,name)
			//fmt.Println(result)
			mutex.Lock()
			*resultlist=append(*resultlist,task.Poc.Name)
			mutex.Unlock()
		}
	}
}
