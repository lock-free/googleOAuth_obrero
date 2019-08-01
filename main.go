package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/obrero"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const APP_CONFIG = "/data/app.json"

type GoogleUser struct {
	ID            string
	Email         string
	VerifiedEmail string
	Name          string
	GivenName     string
	FamilyName    string
	Link          string
	Picture       string
	Locale        string
	HD            string
}

type AppConfig struct {
	GoogleOAuthConfig oauth2.Config
}

func main() {
	// read conf
	var appConfig AppConfig
	err := obrero.ReadJson(APP_CONFIG, &appConfig)

	if err != nil {
		panic(err)
	}

	var googleOAuthConfig = appConfig.GoogleOAuthConfig

	obrero.StartBlockWorker(func(*gopcp_stream.StreamServer) *gopcp.Sandbox {
		return gopcp.GetSandbox(map[string]*gopcp.BoxFunc{
			"getServiceType": gopcp.ToSandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				return "google_oauth_obrero", nil
			}),

			// (constructOAuthUrl, callbackHost, callbackEndPoint)
			"constructOAuthUrl": gopcp.ToSandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				if len(args) < 2 {
					return nil, errors.New("missing callbackHost or callbackEndPoint parameter")
				}
				callbackHost, ok := args[0].(string)
				if !ok {
					return nil, errors.New("wrong type of callbackHost parameter")
				}
				callbackEndPoint, ok := args[1].(string)
				if !ok {
					return nil, errors.New("wrong type of callbackEndPoint parameter")
				}
				// copy and change redirect
				var goc = oauth2.Config{
					ClientID:     googleOAuthConfig.ClientID,
					ClientSecret: googleOAuthConfig.ClientSecret,
					Endpoint:     google.Endpoint,
					RedirectURL:  callbackHost + callbackEndPoint + "?host=" + callbackHost,
					Scopes:       googleOAuthConfig.Scopes,
				}

				// construct redirect url
				return goc.AuthCodeURL("state"), nil
			}),

			// (getUserInfo, callbackHost, url, callbackEndPoint)
			"getUserInfo": gopcp.ToSandboxFun(func(args []interface{}, attachment interface{}, pcpServer *gopcp.PcpServer) (interface{}, error) {
				if len(args) < 3 {
					return nil, errors.New("missing callbackHost or url parameter")
				}
				callbackHost, ok := args[0].(string)
				if !ok {
					return nil, errors.New("wrong type of callbackHost parameter")
				}
				uri, ok := args[1].(string)
				if !ok {
					return nil, errors.New("wrong type of url parameter")
				}
				callbackEndPoint, ok := args[2].(string)
				if !ok {
					return nil, errors.New("wrong type of callbackEndPoint parameter")
				}
				// copy and change redirect
				var goc = oauth2.Config{
					ClientID:     googleOAuthConfig.ClientID,
					ClientSecret: googleOAuthConfig.ClientSecret,
					Endpoint:     google.Endpoint,
					RedirectURL:  callbackHost + callbackEndPoint + "?host=" + callbackHost,
					Scopes:       googleOAuthConfig.Scopes,
				}

				return GetUserInfoFromGoogle(&goc, uri)
			}),
		})
	}, obrero.WorkerStartConf{
		PoolSize:            2,
		Duration:            20 * time.Second,
		RetryDuration:       20 * time.Second,
		NAGetClientMaxRetry: 3,
	})
}

// call this to get user when callback
func GetUserInfoFromGoogle(conf *oauth2.Config, uri string) (googleUser GoogleUser, err error) {
	var (
		u        *url.URL
		token    *oauth2.Token
		response *http.Response
		content  []byte
	)
	u, err = url.Parse(uri)
	if err != nil {
		return
	}

	qm := u.Query()
	state, code := qm.Get("state"), qm.Get("code")

	if state != "state" {
		err = fmt.Errorf("Invalid OAuth state")
		return
	}

	token, err = conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		err = fmt.Errorf("code exchange failed: %s", err.Error())
		return
	}

	response, err = http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		err = fmt.Errorf("failed getting user info: %s", err.Error())
		return
	}

	defer response.Body.Close()
	content, err = ioutil.ReadAll(response.Body)
	if err != nil {
		err = fmt.Errorf("failed reading response body: %s", err.Error())
		return
	}

	err = json.Unmarshal([]byte(content), &googleUser)

	return
}
