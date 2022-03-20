package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// sshloginCmd represents the sshlogin command
var sshloginCmd = &cobra.Command{
	Use:   "sshlogin",
	Short: "Login using a user name, password, or key",
	Run: func(cmd *cobra.Command, args []string) {
		sshlogin()
	},
}

func sshlogin()  {
	if Hosts==""{
		Checkerr(fmt.Errorf("login mode must set Host,use (-H 172.16.95.1) to set\n"))
		os.Exit(0)
	}
	if Username==""{
		Checkerr(fmt.Errorf("login mode must set username\n"))
		os.Exit(0)
	}
	if login_key{
		client,err:=ssh_connect_publickeys(Hosts,Username,key_path)
		Checkerr_exit(err)
		ssh_login(client)
	}else {
		if Password==""{
			Checkerr(fmt.Errorf("Musst set password"))
			os.Exit(0)}
		client,err:=ssh_connect_userpass(Hosts,Username,Password)
		Checkerr_exit(err)
		ssh_login(client)
	}
}

func init() {
	exploitCmd.AddCommand(sshloginCmd)
	sshloginCmd.Flags().StringVarP(&Hosts,"host","H","","Set ssh server host")
	sshloginCmd.Flags().IntVarP(&ssh_port,"port","p",22,"Set ssh server port")
	sshloginCmd.Flags().StringVarP(&Username,"username","U","","Set ssh username")
	sshloginCmd.Flags().StringVarP(&Password,"password","P","","Set ssh password")
	sshloginCmd.Flags().BoolVarP(&login_key,"login_key","k",false,"Use public key login")
	sshloginCmd.Flags().StringVarP(&key_path,"keypath","d","","Set public key path")
}
