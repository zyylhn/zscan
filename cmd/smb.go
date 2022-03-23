package cmd

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/stacktitan/smb/gss"
	"github.com/stacktitan/smb/ntlmssp"
	"github.com/stacktitan/smb/smb/encoder"
	"io"
	"log"
	"net"
	"runtime/debug"
	"time"
)

var smb_port int
var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "burp smb usernamae and password",
	PreRun: func(cmd *cobra.Command, args []string) {
		SaveInit()
		PrintScanBanner("smb")
	},
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		defer func() {
			Output_endtime(start)
		}()
		smbmode()
	},
}

func smbmode()  {
	burp_smb()
}

func burp_smb()  {
	GetHost()
	if Username==""{
		Username="Administrator,admin"
	}
	ips := Parse_IP(Hosts)
	aliveserver:=NewPortScan(ips,[]int{smb_port},Connectsmbburp,true)
	_=aliveserver.Run()
}

func Connectsmbburp(ip string,port int) (string,int,error,[]string) {
	conn, err := Getconn( ip, port)
	if conn != nil {
		_ = conn.Close()
		fmt.Printf(White(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port)))
		fmt.Println(Yellow("\rStart burp smb : ",ip))
		startburp:=NewBurp(Password,Username,Userdict,Passdict,ip,smb_auth,burpthread)
		startburp.Run()
	}
	return ip, port, err,nil
}

func smb_auth(username,password,ip string) (error,bool,string) {
	result := false
	domain,user:=getusername(username)
	options := Options{
		Host:        ip,
		Port:        445,
		User:        user,
		Password:    password,
		Domain:      domain,
		Workstation: "",
	}
	session, err := NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			result = true
		}
	}
	return err, result,"smb"
}

type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	securityMode      uint16
	messageID         uint64
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
	options           Options
	trees             map[string]uint32
}

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
}

const ProtocolSmb2 = "\xFESMB"
const StatusOk = 0x00000000
const StatusMoreProcessingRequired = 0xc0000016
const StatusInvalidParameter = 0xc000000d
const StatusLogonFailure = 0xc000006d
const StatusUserSessionDeleted = 0xc0000203
const DialectSmb_2_1 = 0x0210
const (
	CommandNegotiate uint16 = iota
	CommandSessionSetup
	CommandTreeConnect
	CommandTreeDisconnect
)
const (
	_ uint16 = iota
	SecurityModeSigningEnabled
	SecurityModeSigningRequired
)
const (
	_ byte = iota
)
var StatusMap = map[uint32]string{
	StatusOk:                     "OK",
	StatusMoreProcessingRequired: "More Processing Required",
	StatusInvalidParameter:       "Invalid Parameter",
	StatusLogonFailure:           "Logon failed",
	StatusUserSessionDeleted:     "User session deleted",
}

type Header struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

type NegotiateReq struct {
	Header
	StructureSize   uint16
	DialectCount    uint16 `smb:"count:Dialects"`
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGuid      []byte `smb:"fixed:16"`
	ClientStartTime uint64
	Dialects        []uint16
}

type NegotiateRes struct {
	Header
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16
	ServerGuid           []byte `smb:"fixed:16"`
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	Reserved2            uint32
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenResp
}

type TreeConnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
	PathOffset    uint16 `smb:"offset:Path"`
	PathLength    uint16 `smb:"len:Path"`
	Path          []byte
}

type TreeConnectRes struct {
	Header
	StructureSize uint16
	ShareType     byte
	Reserved      byte
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

type TreeDisconnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeDisconnectRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  0,
		Status:        0,
		Command:       0,
		Credits:       0,
		Flags:         0,
		NextCommand:   0,
		MessageID:     0,
		Reserved:      0,
		TreeID:        0,
		SessionID:     0,
		Signature:     make([]byte, 16),
	}
}

func NewSession(opt Options, debug bool) (s *Session, err error) {

	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	//conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
	conn,err:=Getconn(opt.Host, opt.Port)
	if err != nil {
		return
	}

	s = &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		debug:             debug,
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		conn:              conn,
		options:           opt,
		trees:             make(map[string]uint32),
	}

	s.Debug("Negotiating protocol", nil)
	err = s.NegotiateProtocol()
	if err != nil {
		return
	}

	return s, nil
}

func (s *Session) Debug(msg string, err error) {
	if s.debug {
		log.Println("[ DEBUG ] ", msg)
		if err != nil {
			debug.PrintStack()
		}
	}
}

func (s *Session) NegotiateProtocol() error {
	negReq := s.NewNegotiateReq()
	s.Debug("Sending NegotiateProtocol request", nil)
	buf, err := s.send(negReq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	negRes := NewNegotiateRes()
	s.Debug("Unmarshalling NegotiateProtocol response", nil)
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if negRes.Header.Status != StatusOk {
		return errors.New(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return errors.New(fmt.Sprintf(
			"Unknown security type OID [expecting %s]: %s\n",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID))
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		s.Debug("", err)
		return err
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		return errors.New("Server does not support NTLMSSP")
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	s.Debug("Sending SessionSetup1 request", nil)
	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		s.Debug("", err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err = encoder.Marshal(ssreq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.send(ssreq)
	if err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	s.Debug("Unmarshalling SessionSetup1 response", nil)
	if err := encoder.Unmarshal(buf, &ssres); err != nil {
		s.Debug("", err)
		return err
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		s.Debug("", err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, _ := StatusMap[negRes.Header.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.sessionID = ssres.Header.SessionID

	s.Debug("Sending SessionSetup2 request", nil)
	ss2req, err := s.NewSessionSetup2Req()
	if err != nil {
		s.Debug("", err)
		return err
	}

	var auth ntlmssp.Authenticate
	if s.options.Hash != "" {
		// Hash present, use it for auth
		s.Debug("Performing hash-based authentication", nil)
		auth = ntlmssp.NewAuthenticateHash(s.options.Domain, s.options.User, s.options.Workstation, s.options.Hash, challenge)
	} else {
		// No hash, use password
		s.Debug("Performing password-based authentication", nil)
		auth = ntlmssp.NewAuthenticatePass(s.options.Domain, s.options.User, s.options.Workstation, s.options.Password, challenge)
	}

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		s.Debug("", err)
		return err
	}
	resp2 := ss2req.SecurityBlob
	resp2.ResponseToken = responseToken
	ss2req.SecurityBlob = resp2
	ss2req.Header.Credits = 127
	buf, err = encoder.Marshal(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.send(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling SessionSetup2 response", nil)
	var authResp Header
	if err := encoder.Unmarshal(buf, &authResp); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if authResp.Status != StatusOk {
		status, _ := StatusMap[authResp.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.IsAuthenticated = true

	s.Debug("Completed NegotiateProtocol and SessionSetup", nil)
	return nil
}

func (s *Session) TreeConnect(name string) error {
	s.Debug("Sending TreeConnect request ["+name+"]", nil)
	req, err := s.NewTreeConnectReq(name)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	var res TreeConnectRes
	s.Debug("Unmarshalling TreeConnect response ["+name+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if res.Header.Status != StatusOk {
		return errors.New("Failed to connect to tree: " + StatusMap[res.Header.Status])
	}
	s.trees[name] = res.Header.TreeID

	s.Debug("Completed TreeConnect ["+name+"]", nil)
	return nil
}

func (s *Session) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range s.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := errors.New("Unable to find tree path for disconnect")
		s.Debug("", err)
		return err
	}

	s.Debug("Sending TreeDisconnect request ["+name+"]", nil)
	req, err := s.NewTreeDisconnectReq(treeid)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling TreeDisconnect response for ["+name+"]", nil)
	var res TreeDisconnectRes
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if res.Header.Status != StatusOk {
		return errors.New("Failed to disconnect from tree: " + StatusMap[res.Header.Status])
	}
	delete(s.trees, name)

	s.Debug("TreeDisconnect completed ["+name+"]", nil)
	return nil
}

func (s *Session) Close() {
	s.Debug("Closing session", nil)
	for k, _ := range s.trees {
		s.TreeDisconnect(k)
	}
	s.Debug("Closing TCP connection", nil)
	s.conn.Close()
	s.Debug("Session close completed", nil)
}

func (s *Session) send(req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		s.Debug("", err)
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		s.Debug("", err)
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		s.Debug("", err)
		return
	}
	if size > 0x00FFFFFF {
		return nil, errors.New("Invalid NetBIOS Session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}
	if uint32(l) != size {
		return nil, errors.New("Message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("Protocol Not Implemented")
	case ProtocolSmb2:
	}

	s.messageID++
	return data, nil
}

func (s *Session) NewSessionSetup2Req() (SessionSetup2Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup2Req{}, err
	}

	if s.sessionID == 0 {
		return SessionSetup2Req{}, errors.New("Bad session ID for session setup 2 message")
	}

	// Session setup request #2
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Req{}, err
	}
	resp.ResponseToken = data

	return SessionSetup2Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &resp,
	}, nil
}

func (s *Session) NewTreeConnectReq(name string) (TreeConnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeConnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	path := fmt.Sprintf("\\\\%s\\%s", s.options.Host, name)
	return TreeConnectReq{
		Header:        header,
		StructureSize: 9,
		Reserved:      0,
		PathOffset:    0,
		PathLength:    0,
		Path:          encoder.ToUnicode(path),
	}, nil
}


func (s *Session) NewTreeDisconnectReq(treeId uint32) (TreeDisconnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeDisconnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = treeId

	return TreeDisconnectReq{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}

func (s *Session) NewNegotiateReq() NegotiateReq {
	header := newHeader()
	header.Command = CommandNegotiate
	header.CreditCharge = 1
	header.MessageID = s.messageID

	dialects := []uint16{
		uint16(DialectSmb_2_1),
	}
	return NegotiateReq{
		Header:          header,
		StructureSize:   36,
		DialectCount:    uint16(len(dialects)),
		SecurityMode:    SecurityModeSigningEnabled,
		Reserved:        0,
		Capabilities:    0,
		ClientGuid:      make([]byte, 16),
		ClientStartTime: 0,
		Dialects:        dialects,
	}
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:               newHeader(),
		StructureSize:        0,
		SecurityMode:         0,
		DialectRevision:      0,
		Reserved:             0,
		ServerGuid:           make([]byte, 16),
		Capabilities:         0,
		MaxTransactSize:      0,
		MaxReadSize:          0,
		MaxWriteSize:         0,
		SystemTime:           0,
		ServerStartTime:      0,
		SecurityBufferOffset: 0,
		SecurityBufferLength: 0,
		Reserved2:            0,
		SecurityBlob:         &gss.NegTokenInit{},
	}
}

func (s *Session) NewSessionSetup1Req() (SessionSetup1Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup1Req{}, err
	}

	if s.sessionID != 0 {
		return SessionSetup1Req{}, errors.New("Bad session ID for session setup 1 message")
	}

	// Initial session setup request
	init, err := gss.NewNegTokenInit()
	if err != nil {
		return SessionSetup1Req{}, err
	}
	init.Data.MechToken = data

	return SessionSetup1Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}, nil
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}


func validateOptions(opt Options) error {
	if opt.Host == "" {
		return errors.New("Missing required option: Host")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return errors.New("Invalid or missing value: Port")
	}
	return nil
}



func init() {
	blastCmd.AddCommand(smbCmd)
	smbCmd.Flags().StringVar(&Hostfile,"hostfile","","Set host file")
	smbCmd.Flags().StringVarP(&Hosts,"host","H","","Set smb server host")
	smbCmd.Flags().IntVarP(&smb_port,"port","p",445,"Set smb server port")
	smbCmd.Flags().IntVarP(&burpthread,"burpthread","",100,"Set burp password thread(recommend not to change)")
	smbCmd.Flags().StringVarP(&Username,"username","U","","Set smb username eg:admin,domain/administrator")
	smbCmd.Flags().StringVarP(&Password,"password","P","","Set smb password")
	smbCmd.Flags().StringVarP(&Userdict,"userdict","","","Set smb userdict path")
	smbCmd.Flags().StringVarP(&Passdict,"passdict","","","Set smb passworddict path")
}
