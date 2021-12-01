package cmd

import (
	"fmt"
	gosnmp2 "github.com/gosnmp/gosnmp"
	"github.com/spf13/cobra"
	"time"
)

var get string
var walk string
var snmpVersion string
var snmpPort int
var snmpPassword string
var snmpResult = make(map[string][]string)
var listoid bool

var snmpCmd = &cobra.Command{
	Use:   "snmp",
	Short: "snmp scan",
	PreRun: func(cmd *cobra.Command, args []string) {
		CreatFile(Output_result, Path_result)
		PrintScanBanner("snmp")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		snmpScan()
	},
}

func snmpScan() {
	GetHost()
	if listoid{
		fmt.Println("0: 系统基本信息    \tSysDesc             \tGET \t1.3.6.1.2.1.1.1.0")
		fmt.Println("1: 监控时间      \tsysUptime           \tGET \t1.3.6.1.2.1.1.3.0")
		fmt.Println("2: 系统联系人     \tsysContact          \tGET \t1.3.6.1.2.1.1.4.0")
		fmt.Println("3: 获取机器名     \tSysName             \tGET \t1.3.6.1.2.1.1.5.0")
		fmt.Println("4: 机器所在位置    \tSysLocation         \tGET \t1.3.6.1.2.1.1.6.0")
		fmt.Println("5: 机器提供的服务   \tSysService          \tGET \t1.3.6.1.2.1.1.7.0")
		fmt.Println("6: 系统运行的进程列表 \thrSWRunName         \tWALK\t1.3.6.1.2.1.25.4.2.1.2")
		fmt.Println("7: 系统安装的软件列表 \thrSWInstalledName   \tWALK\t1.3.6.1.2.1.25.6.3.1.2")
		fmt.Println("8: 网络接口列表    \tipAdEntAddr         \tWALK\t1.3.6.1.2.1.4.20.1.1")
		return
	}
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver := NewPortScan(ips, []int{161}, snmpIpInfo,true)
	aliveserver.Run()
	printSnmpResult()
}

func snmpIpInfo(ip string, port int) (string, int, error, []string) {
	startburp := NewBurp(snmpPassword, Username, Userdict, Passdict, ip, snmpConnect, burpthread)
	startburp.Run()
	return ip, port, nil, []string{}
}

func snmpConnect(_ string, password string, ip string) (error, bool, string) {
	gosnmp := InitgoSnmp(ip, snmpPort, password, snmpVersion)
	err := gosnmp.Connect()
	if err != nil {
		return err, false, "snmp"
	}
	defer gosnmp.Conn.Close()
	res, err := gosnmp.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"})
	if err != nil {
		return err, false, "snmp"
	}
	parseSnmpRes(ip, res.Variables)
	if get!="" {
		res, err = gosnmp.Get([]string{get})
		if err != nil {
			return err, false, "snmp"
		}
		parseSnmpRes(ip, res.Variables)
	}else if walk!=""{
		res,err := gosnmp.BulkWalkAll(walk)
		if err != nil {
			return err, false, "snmp"
		}
		parseSnmpRes(ip,res)
	}
	return nil, true, "snmp"
}

func InitgoSnmp(ip string, port int, password string, version string) *gosnmp2.GoSNMP {
	gosnmp := &gosnmp2.GoSNMP{
		Target:    ip,
		Port:      uint16(port),
		Community: password,
		Transport: "udp",
		Timeout:   2 * time.Second,
		Retries:   1,
		MaxOids:   gosnmp2.MaxOids,
	}
	switch version {
	case "1":
		gosnmp.Version = gosnmp2.Version1
	case "2c":
		gosnmp.Version = gosnmp2.Version2c
	case "3":
		gosnmp.Version = gosnmp2.Version3
	}
	return gosnmp
}

func parseSnmpRes(ip string, pdus []gosnmp2.SnmpPDU) {
	var results []string
	for _, pdu := range pdus {
		result := pdu.Name
		switch pdu.Type {
		case gosnmp2.OctetString:
			bytes := pdu.Value.([]byte)
			result += fmt.Sprintf("  %s\n", string(bytes))
		default:
			result += fmt.Sprintf("  %d\n", gosnmp2.ToBigInt(pdu.Value))
		}
		results = append(results, result)
	}
	snmpResult[ip] = results
}

func printSnmpResult() {
	Output("\n\r===========================snmp result list=============================\n", LightGreen)
	for ip, results := range snmpResult {
		Output("Target:"+ip+"\n", LightBlue)
		for _, result := range results {
			Output("\t"+result, White)
		}
	}
}

func init() {
	rootCmd.AddCommand(snmpCmd)
	snmpCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	snmpCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set target")
	//snmpCmd.MarkFlagRequired("host")
	snmpCmd.Flags().IntVarP(&snmpPort, "port", "p", 161, "Set `port`")
	snmpCmd.Flags().BoolVarP(&listoid, "listoid", "l", false, "List commonly used OIDs")
	snmpCmd.Flags().StringVar(&snmpPassword, "password", "public", "set a password")
	snmpCmd.Flags().StringVar(&Passdict, "passwordfile", "", "passwords dict file, eg: ./dict/password.txt")
	snmpCmd.Flags().IntVarP(&burpthread, "burpthread", "", 100, "Set burp password thread(recommend not to change)")
	snmpCmd.Flags().StringVar(&snmpVersion, "version", "2c", "specifies SNMP version to use. 1|2c|3 ")
	snmpCmd.Flags().StringVar(&get, "get", "", "set an oid")
	snmpCmd.Flags().StringVar(&walk, "walk", "", "set an oid")

}
