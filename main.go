package main

import (
	"encoding/json"
	"fmt"
	"github.com/lock-free/gopcp"
	"github.com/lock-free/gopcp_stream"
	"github.com/lock-free/obrero/napool"
	"github.com/lock-free/obrero/stdserv"
	"github.com/lock-free/obrero/utils"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"net/url"
)

const APP_CONFIG = "/data/app.json"

type AppConfig struct {
	GoogleOAuthConfig oauth2.Config
}

func main() {
	var appConfig AppConfig
	stdserv.StartStdWorker(&appConfig, func(naPools *napool.NAPools, s *gopcp_stream.StreamServer) map[string]*gopcp.BoxFunc {
		return map[string]*gopcp.BoxFunc{
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

				var googleOAuthConfig = appConfig.GoogleOAuthConfig
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

				var googleOAuthConfig = appConfig.GoogleOAuthConfig
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
		}
	}, stdserv.StdWorkerConfig{
		ServiceName: "google_oauth_obrero",
	})
}

func GetAccessToken(conf *oauth2.Config, uri string) (token *oauth2.Token, err error) {
	var (
		u *url.URL
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
	return
}

func GetGoogleClient(conf *oauth2.Config, uri string) (*http.Client, error) {
	token, err := GetAccessToken(conf, uri)
	if err != nil {
		return nil, err
	}
	return conf.Client(context.Background(), token), nil
}

// call this to get user when callback
func GetUserInfoFromGoogle(conf *oauth2.Config, uri string) (googleUser interface{}, err error) {
	var (
		response *http.Response
		token    *oauth2.Token
		content  []byte
	)
	token, err = GetAccessToken(conf, uri)
	if err != nil {
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
