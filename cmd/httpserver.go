package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var httpserveraddr string
var dir string
var maxupload int
//var allowupload bool

var httpserverCmd = &cobra.Command{
	Use:   "http",
	Short: "Start an authentication HTTP server",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("httpserver")
	},
	Run: func(cmd *cobra.Command, args []string) {
		httpserver()
	},
}

type logger struct {
	httplog http.Handler
}

func (l *logger) ServeHTTP(w http.ResponseWriter,req *http.Request)  {
	l.httplog.ServeHTTP(w,req)
	//log.Println(req.RemoteAddr," request ",req.URL)
	Output(string(time.Now().AppendFormat([]byte("\r"), l1))+" "+req.RemoteAddr+" request "+req.URL.String()+"\n",White)
	maxUploadSize:=maxupload*1024*1024
	//if req.Method == "GET" {
	var urlip string
	var urlport string
	if a:=strings.Split(httpserveraddr,":");a[0]=="0.0.0.0"{
		urlip="127.0.0.1"
		urlport=a[1]
	}else {
		urlip=a[0]
		urlport=a[1]
	}

	w.Write([]byte(fmt.Sprintf("<html>\n<head>\n\t<title>Upload file</title>\n</head>\n<body>\n<form enctype=\"multipart/form-data\" action=\"http://%v:%v/\" method=\"post\">\n\t<input type=\"file\" name=\"uploadFile\" />\n\t<input type=\"submit\" value=\"upload\" />\n</form>\n</body>\n</html>",urlip,urlport)))
	//}
	if req.Method=="POST"{
		file, fileHeader, err := req.FormFile("uploadFile")
		if err != nil {
			renderError(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()
		// Get and print out file size
		fileSize := fileHeader.Size
		fmt.Printf("File size (bytes): %v\n", fileSize)
		// validate file size
		if fileSize > int64(maxUploadSize) {
			renderError(w, "FILE_TOO_BIG", http.StatusBadRequest)
			return
		}
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			renderError(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		fileName := fileHeader.Filename
		fmt.Println(req.URL)
		newPath := filepath.Join(dir, fileName)
		if !filepath.IsAbs(newPath){
			newPath,err=filepath.Abs(newPath)
			Checkerr(err)
		}
		newFile, err := os.Create(newPath)
		if err != nil {
			renderError(w, "CANT_WRITE_FILE", http.StatusInternalServerError)
			return
		}
		defer newFile.Close() // idempotent, okay to call twice
		if _, err := newFile.Write(fileBytes); err != nil || newFile.Close() != nil {
			renderError(w, "CANT_WRITE_FILE", http.StatusInternalServerError)
			return
		}
		successmessage:=fmt.Sprintf("SUCCESS UPLOAD  Save to %v",newFile.Name())
		Output(successmessage,White)
		w.Write([]byte(successmessage))
	}
}

func httpserver()  {
	fs := http.FileServer(http.Dir(dir))
	var l logger
	if Username==""&&Password==""{
		l=logger{http.StripPrefix("/", fs)}
	}else {
		l=logger{SimpleBasicAuth(Username, Password)(http.FileServer(http.Dir(dir)))}
	}
	http.ListenAndServe(httpserveraddr, &l)
}

func renderError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

//身份认证
type basicAuth struct {
	h    http.Handler
	opts AuthOptions
}
//身份认证
type AuthOptions struct {
	Realm               string
	User                string
	Password            string
	AuthFunc            func(string, string, *http.Request) bool
	UnauthorizedHandler http.Handler
}
//身份认证
func (b basicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.opts.UnauthorizedHandler == nil {
		b.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	if b.authenticate(r) == false {
		b.requestAuth(w, r)
		return
	}
	b.h.ServeHTTP(w, r)
}
//身份认证
func (b *basicAuth) authenticate(r *http.Request) bool {
	const basicScheme string = "Basic "

	if r == nil {
		return false
	}
	if b.opts.AuthFunc == nil && b.opts.User == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, basicScheme) {
		return false
	}
	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return false
	}
	creds := bytes.SplitN(str, []byte(":"), 2)
	if len(creds) != 2 {
		return false
	}
	givenUser := string(creds[0])
	givenPass := string(creds[1])
	if b.opts.AuthFunc == nil {
		b.opts.AuthFunc = b.simpleBasicAuthFunc
	}

	return b.opts.AuthFunc(givenUser, givenPass, r)
}
//身份认证
func (b *basicAuth) simpleBasicAuthFunc(user, pass string, r *http.Request) bool {
	givenUser := sha256.Sum256([]byte(user))
	givenPass := sha256.Sum256([]byte(pass))
	requiredUser := sha256.Sum256([]byte(b.opts.User))
	requiredPass := sha256.Sum256([]byte(b.opts.Password))
	if subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
		subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1 {
		return true
	}

	return false
}
//身份认证
func (b *basicAuth) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, b.opts.Realm))
	b.opts.UnauthorizedHandler.ServeHTTP(w, r)
}
//身份认证
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
//身份认证
func BasicAuth(o AuthOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return basicAuth{h, o}
	}
	return fn
}
//身份认证
func SimpleBasicAuth(user, password string) func(http.Handler) http.Handler {
	opts := AuthOptions{
		Realm:    "Restricted",
		User:     user,
		Password: password,
	}
	return BasicAuth(opts)
}

func init() {
	serverCmd.AddCommand(httpserverCmd)
	httpserverCmd.Flags().IntVarP(&maxupload,"size","s",20,"set max upload files size(mb)")
	//httpserverCmd.Flags().BoolVarP(&allowupload,"upload","u",false,"allow upload,/u indicates the file upload path（Unauthorized authorization exists，finished off）")
	httpserverCmd.Flags().StringVarP(&httpserveraddr,"addr","a","0.0.0.0:7001","set http server addr")
	httpserverCmd.Flags().StringVarP(&Username,"user","U","","Set the authentication user")
	httpserverCmd.Flags().StringVarP(&Password,"pass","P","","Set the authentication password")
	httpserverCmd.Flags().StringVarP(&dir,"dir","d",".","set HTTP server root directory")
}
