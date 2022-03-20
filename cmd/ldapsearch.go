package cmd

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	"strings"
)

var BaseDn	string
var Filter string
var Attribut string
var SizeLimit int
var Or bool
var Listcmd bool
var ldapsearchCmd = &cobra.Command{
	Use:   "ldapsearch",
	Short: "Ldap queries",
	Run: func(cmd *cobra.Command, args []string) {
		ldapSearch()
	},
}

func ldapSearch()  {
	if Listcmd{
		cmd:=GetCommonQueries()
		for k,v:=range cmd{
			fmt.Println(LightCyan(k)," : ",LightGreen(v))
		}
		return
	}
	if Hosts==""{
		fmt.Println(Red("must set host"))
		return
	}
	if Username==""{
		fmt.Println(Red("must set user"))
		return
	}
	if Password==""{
		fmt.Println(Red("must set pass"))
		return
	}
	conn,err:=LoginBind(Username,Password,Hosts)
	if err!=nil{
		fmt.Println(Red("身份验证失败：",err))
		return
	}
	result,err:=SearchLdap(conn,BaseDn,Filter,Attribut,SizeLimit)
	if err!=nil{
		fmt.Println(err)
		return
	}
	re:=OutputResult(Attribut,result,Or)
	switch re.(type) {
	case *ldap.SearchResult:
		re.(*ldap.SearchResult).PrettyPrint(2)
	case map[string][]string:
		for k,v:=range re.(map[string][]string){
			fmt.Println(LightCyan(k))
			for _,r:=range v{
				fmt.Println(LightGreen(r))
			}
		}
	}
}

func SearchLdap(conn *ldap.Conn,baseDn,filter,attributeStr string,sizeLimit int) (*ldap.SearchResult,error) {
	var attributeList []string
	if attributeStr!=""{
		attributeList=strings.Split(attributeStr,",")
	}
	sql:=ldap.NewSearchRequest(baseDn, ldap.ScopeWholeSubtree,ldap.NeverDerefAliases,sizeLimit,0,false,filter,attributeList,nil)
	return conn.Search(sql)
}

func OutputResult(attstr string,result *ldap.SearchResult,or bool) interface{} {
	remap:=make(map[string][]string)
	attlist:=strings.Split(attstr,",")
	if len(result.Entries)>0{
		for _,item:=range result.Entries{
			if attstr!=""{
				for _,att:=range attlist{
					cn:=item.GetAttributeValues(att)
					if len(cn)>0{
						for _,i:=range cn{
							remap[item.DN]=append(remap[item.DN],fmt.Sprint("\t"+att+":"+i))
						}
					}
				}
				if !or{
					if len(remap[item.DN])<len(attlist){
						delete(remap,item.DN)
					}
				}
			}
		}
	}
	if len(remap)!=0{
		return remap
	}else {
		return result
	}
}

func GetCommonQueries() map[string]string {
	var cmd map[string]string
	cmd= make(map[string]string)
	cmd["获取所有邮件地址"]="-d \"CN=users,DC=lhn,DC=com\" -f \"(objectClass=*)\" -a mail"
	cmd["查询域控制器主机名"]="-d \"OU=Domain Controllers,DC=lhn,DC=com\" -f \"(objectClass=*)\" -a dNSHostName,operatingSystem,operatingSystemVersion"
	cmd["查询域管理员"]="-d \"CN=Domain Admins,CN=users,DC=lhn,DC=com\" -f \"(member=*)\" -a member"
	cmd["查询所有域用户"]="-d \"CN=users,DC=lhn,DC=com\" -f \"(sAMAccountType=805306368)\" -a sAMAccountName"
	cmd["查看加入域的所有计算机名(不包括域控)"]="-dn \"CN=Computers,DC=lhn,DC=com\" -f \"(sAMAccountType=805306369)\" -a dNSHostName,operatingSystem,operatingSystemVersion"
	return cmd
}

func init() {
	exploitCmd.AddCommand(ldapsearchCmd)
	ldapsearchCmd.Flags().StringVarP(&Username,"user","U","","set user")
	ldapsearchCmd.Flags().StringVarP(&Password,"pass","P","","set user password")
	ldapsearchCmd.Flags().StringVarP(&Hosts,"host","H","","set target")
	ldapsearchCmd.Flags().StringVarP(&BaseDn,"Dn","d","","set base dn")
	ldapsearchCmd.Flags().StringVarP(&Filter,"filter","f","","set Attribute filtering")
	ldapsearchCmd.Flags().StringVarP(&Attribut,"attribute","a","","Sets the attribute to be queried")
	ldapsearchCmd.Flags().IntVar(&SizeLimit,"limit",0,"Set the number of data items to return")
	ldapsearchCmd.Flags().BoolVar(&Or,"or",false,"Multiple attributes return logic（default and）")
	ldapsearchCmd.Flags().BoolVar(&Listcmd,"list",false,"Listing common commands")
}