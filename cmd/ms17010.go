package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"strings"
	"time"
)

var (
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

var ms17010Cmd = &cobra.Command{
	Use:   "ms17010",
	Short: "MS17_010 scan",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("ms17010")
	},
	Run: func(cmd *cobra.Command, args []string) {
		ms17010()
	},
}

func ms17010()  {
	GetHost()
	ips, err := Parse_IP(Hosts)
	Checkerr(err)
	aliveserver:=NewPortScan(ips,[]int{445},Connect17010,true)
	r:=aliveserver.Run()
	Printresult(r)
}


func Connect17010(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn(fmt.Sprintf("%v:%v",ip,port))
	if conn != nil{
		defer conn.Close()
		_,r:=ms17010info(conn,ip)
		return ip,port,nil,r
	}
	return ip,port,err,nil
}

func ms17010info(conn net.Conn,ip string) (error,[]string) {
	r:=[]string{}
	err := conn.SetDeadline(time.Now().Add(Timeout))
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err,nil
	}
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return err,nil
	}
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err,nil
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return err,nil
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return err,nil
	}
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return err,nil
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		err:= fmt.Errorf("can't determine whether target is vulnerable or not\n")
		return err,nil
	}
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("[-]", ip+":445", "ms17010 invalid session setup AndX response")
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	_, err = conn.Write(treeConnectRequest)
	if err != nil {
		return err,nil
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err,nil
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		return err,nil
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err,nil
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		result := fmt.Sprintf("Find MS17-010\t(%s)",os)
		Output(fmt.Sprintf("\r[+]%s    Find MS17-010\t(%s)\n", ip, os),LightGreen)
		r=append(r,result)
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, err = conn.Write(trans2SessionSetupRequest)
		if err != nil {
			return err,nil
		}
		if n, err := conn.Read(reply); err != nil || n < 36 {
			return err,nil
		}

		//if reply[34] == 0x51 {
		//	result := fmt.Sprintf("[+] %s has DOUBLEPULSAR SMB IMPLANT", ip)
		//	fmt.Println(result)
		//}

	} else {
		result := fmt.Sprintf("(%s)",os)
		r=append(r,result)
	}
	return nil,r
}


func init() {
	rootCmd.AddCommand(ms17010Cmd)
	ms17010Cmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	ms17010Cmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set target")
}
