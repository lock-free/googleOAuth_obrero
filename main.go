package main

import (
	"encoding/json"
	"fmt"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/obrero"
	"github.com/lock-free/obrero/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const APP_CONFIG = "/data/app.json"

type AppConfig struct {
	GoogleOAuthConfig oauth2.Config
}

func main() {
	// read conf
	var appConfig AppConfig
	err := utils.ReadJson(APP_CONFIG, &appConfig)

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
				var (
					callbackHost     string
					callbackEndPoint string
				)

				err := utils.ParseArgs(args, []interface{}{&callbackHost, &callbackEndPoint}, "wrong signature, expect (constructOAuthUrl, callbackHost: String, callbackEndPoint: String)")
				if err != nil {
					return nil, err
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
				var (
					callbackHost     string
					uri              string
					callbackEndPoint string
				)

				err := utils.ParseArgs(args, []interface{}{&callbackHost, &uri, &callbackEndPoint}, "wrong signature, expect (getUserInfo, callbackHost: String, uri: String, callbackEndPoint: String)")
				if err != nil {
					return nil, err
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
func GetUserInfoFromGoogle(conf *oauth2.Config, uri string) (googleUser interface{}, err error) {
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
	// content = {
	//   "id": "123",
	//   "email": "a@gmail.com",
	//   "verified_email": true,
	//   "name": "aaa",
	//   "given_name": "aa",
	//   "family_name": "aaa",
	//   "picture": "https://lh6.googleusercontent.com/dd/cc/bbaaa/photo.jpg",
	//   "locale": "en",
	//   "hd": "aaaa"
	// }
	content, err = ioutil.ReadAll(response.Body)
	if err != nil {
		err = fmt.Errorf("failed reading response body: %s", err.Error())
		return
	}
	fmt.Printf("Get user info from Google, content = %s", googleUser)

	err = json.Unmarshal(content, &googleUser)
	return
}
