package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

const (
	callbackPath = "/auth/callback"
	logoutPath   = "/auth/logout"
	sessionName  = "test_server_session"
)

var (
	clientID,
	clientSecret,
	oidcAuthURL,
	oidcLogoutURL,
	oidcTokenURL,
	oidcUserInfoURL string

	sessionStore *sessions.FilesystemStore
)

func main() {
	initVars()
	http.HandleFunc(callbackPath, callBack)
	http.HandleFunc(logoutPath, logout)

	http.Handle("/", protectMiddleware(http.HandlerFunc(index)))

	log.Println("Listen on http://localhost:3000/")
	log.Fatalln(http.ListenAndServe(":3000", nil))
}

func initVars() {
	endpoint := os.Getenv("OAUTH2_ENDPOINT")
	clientID = os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret = os.Getenv("OAUTH2_CLIENT_SECRET")

	oidcAuthURL = fmt.Sprintf("%s/protocol/openid-connect/auth", endpoint)
	oidcLogoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout", endpoint)
	oidcTokenURL = fmt.Sprintf("%s/protocol/openid-connect/token", endpoint)
	oidcUserInfoURL = fmt.Sprintf("%s/protocol/openid-connect/userinfo", endpoint)

	sessionStore = sessions.NewFilesystemStore("", []byte(os.Getenv("SESSION_KEY")))
	sessionStore.Options.HttpOnly = true
	sessionStore.MaxLength(0)
}

func index(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)

	token, ok := session.Values["access_token"].(string)
	if !ok || token == "" {
		redirectToAuth(w, r)

		return
	}

	userinfo, err := getUserinfo(r.Context(), token)
	if err != nil {
		log.Println(err)
		redirectToAuth(w, r)

		return
	}

	if err := json.NewEncoder(w).Encode(userinfo); err != nil {
		log.Println(err)
	}
}

func redirectToAuth(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := url.Parse(oidcAuthURL)
	if err != nil {
		log.Fatal(err)
	}

	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {fmt.Sprintf("http://%s%s", r.Host, callbackPath)},
		"scope":         {"openid"},
	}.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func callBack(w http.ResponseWriter, r *http.Request) {
	tokens, err := getTokens(r)
	if err != nil {
		errHandler(err, w)
		return
	}

	session, _ := sessionStore.Get(r, sessionName)
	session.Values["access_token"] = tokens.AccessToken
	session.Values["id_token"] = tokens.IDToken
	session.Values["refresh_token"] = tokens.RefreshToken

	if err = session.Save(r, w); err != nil {
		log.Println(err)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)

	accessToken, ok := session.Values["access_token"].(string)
	if !ok || accessToken == "" {
		_, _ = w.Write([]byte("Already logged out"))
		return
	}

	redirectURL, _ := url.Parse(oidcLogoutURL)

	idToken, ok := session.Values["id_token"].(string)

	session.Values["access_token"] = ""
	session.Values["id_token"] = ""
	session.Values["refresh_token"] = ""

	if err := session.Save(r, w); err != nil {
		log.Println(err)
		return
	}

	if !ok || idToken == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	redirectURL.RawQuery = url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {fmt.Sprintf("http://%s%s", r.Host, logoutPath)},
		"id_token_hint":            {idToken},
	}.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func getTokens(r *http.Request) (*tokens, error) {
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          r.URL.Query()["code"],
		"redirect_uri":  {fmt.Sprintf("http://%s%s", r.Host, callbackPath)},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid"},
	}

	req, err := http.NewRequestWithContext(r.Context(), "POST", oidcTokenURL, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	tokens := new(tokens)
	err = json.NewDecoder(res.Body).Decode(tokens)

	return tokens, err
}

func refreshTokens(r *http.Request, refreshToken string) (*tokens, error) {
	values := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(r.Context(), "POST", oidcTokenURL, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	tokens := new(tokens)
	err = json.NewDecoder(res.Body).Decode(tokens)

	return tokens, err
}

func getUserinfo(ctx context.Context, token string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", oidcUserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	userinfo := make(map[string]interface{})
	err = json.NewDecoder(res.Body).Decode(&userinfo)

	return userinfo, err
}

func errHandler(err error, w http.ResponseWriter) {
	log.Println(err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func protectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, sessionName)
		if err != nil {
			errHandler(err, w)
			return
		}

		accessToken, ok := session.Values["access_token"].(string)
		if !ok || accessToken == "" {
			redirectToAuth(w, r)
			return
		}

		isExpired, err := checkTokenExpiration(accessToken)
		if err != nil {
			errHandler(err, w)
			return
		}

		if isExpired {
			tokens, err := refreshTokens(r, session.Values["refresh_token"].(string))
			if err != nil {
				redirectToAuth(w, r)
				return
			}

			session.Values["access_token"] = tokens.AccessToken
			session.Values["id_token"] = tokens.IDToken
			session.Values["refresh_token"] = tokens.RefreshToken
			if err := session.Save(r, w); err != nil {
				errHandler(err, w)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func checkTokenExpiration(token string) (bool, error) {
	payload, err := base64.RawStdEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		return false, err
	}

	data := struct {
		ExpiresAt int64 `json:"exp"`
	}{}
	if err = json.Unmarshal(payload, &data); err != nil {
		return false, err
	}

	now := time.Now().Unix()

	return now > data.ExpiresAt, nil
}
