package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"net/http"
	"strings"
)

var httpserveraddr string
var dir string

var httpserverCmd = &cobra.Command{
	Use:   "httpserver",
	Short: "Start an authentication HTTP server",
	PreRun: func(cmd *cobra.Command, args []string) {
		PrintScanBanner("httpserver")
	},
	Run: func(cmd *cobra.Command, args []string) {
		httpserver()
	},
}

func httpserver()  {
	if Username==""&&Password==""{
		http.ListenAndServe(httpserveraddr, http.FileServer(http.Dir(dir)))
	}
	http.ListenAndServe(httpserveraddr, SimpleBasicAuth(Username, Password)(http.FileServer(http.Dir(dir))))
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
	rootCmd.AddCommand(httpserverCmd)
	httpserverCmd.Flags().StringVarP(&httpserveraddr,"addr","a","0.0.0.0:7001","set http server addr")
	httpserverCmd.Flags().StringVarP(&Username,"user","U","","Set the authentication user")
	httpserverCmd.Flags().StringVarP(&Password,"pass","P","","Set the authentication password")
	httpserverCmd.Flags().StringVarP(&dir,"dir","d",".","set HTTP server root directory")
}
