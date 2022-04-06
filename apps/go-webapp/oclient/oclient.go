package oclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	// "fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	KEYCLOAK  = "keycloak"
	AUTHORIZE = "authorization_code"
	REFRESH   = "refresh_token"
	SECRET    = "secret"
	PKCE      = "pkce"
)

var configURL string = "https://localhost/realms/master"
var issuerURL string = "https://localhost/realms/master"
var penguinIssuerURL string = "https://penguin.linux.test/realms/master"
var clientID string = "my-resource-server"
var clientSecret string = "CsraCM20RwbcHF8SJmenGA930hgblub8"
var redirectURL string = "https://localhost:3000/demo/callback"
var penguinredirectURL string = "http://penguin.linux.test:3000/demo/callback"

type Oclient struct {
	Oauth2Config oauth2.Config
	OidcConfig   *oidc.Config
	Verifier     *oidc.IDTokenVerifier
	State        *State
}

func InitOAuth() (*Oclient, error) {
	oclient := Oclient{}

	parentContext := context.Background()
	ctx := oidc.InsecureIssuerURLContext(parentContext, issuerURL)

	// Provider will be discovered with the discoveryBaseURL, but use issuerURL
	// for future issuer validation.

	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		return &oclient, err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oclient.Oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email"},
	}

	oclient.OidcConfig = &oidc.Config{
		ClientID: clientID,
	}
	oclient.Verifier = provider.Verifier(oclient.OidcConfig)
	oclient.setState()
	return &oclient, nil
}

func InitOclient() error {
	PkceInit()

	return loadConfig("oclient/services.json", &services)
}

//== Services

var services map[string]map[string]string

func loadConfig(fname string, config *map[string]map[string]string) (err error) {
	file, err := os.Open(fname)
	if err != nil {
		return
	}
	defer file.Close()
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	json.Unmarshal([]byte(byteValue), config)
	for k, v := range *config {
		v["client_id"] = os.Getenv(v["client_id"])
		if v["client_id"] == "" {
			err = errors.New("Missing service client_id for " + k)
			return
		}
		v["client_secret"] = os.Getenv(v["client_secret"])
		if v["client_id"] == "" {
			err = errors.New("Missing service client_secret for " + k)
			return
		}
	}
	return
}

//== PKCE

func PkceInit() {
	rand.Seed(time.Now().UnixNano())
}

//string of pkce allowed chars
func PkceVerifier(length int) string {
	if length > 128 {
		length = 128
	}
	if length < 43 {
		length = 43
	}
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

//base64-URL-encoded SHA256 hash of verifier, per rfc 7636
func PkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
	return (challenge)
}

//== State Management

const (
	InitAuthTimeout = 10 //minutes - amount of time user has to complete Authorization and get Access Code from Authorization Server
)

type State struct {
	CreatedAt     time.Time
	Service       string
	AuthType      string
	PkceVerifier  string
	PkceChallenge string
}

var mutex = &sync.Mutex{}

//get the payload for a state, check expiration, and delete
func (oclient *Oclient) getState() (value *State) {
	mutex.Lock()
	v := oclient.State
	n := time.Now().UTC()
	if n.After(v.CreatedAt.Add(InitAuthTimeout * time.Minute)) {
		value = nil //don't accept expired state
	} else {
		value = v
	}
	oclient.State = nil
	defer mutex.Unlock()
	return
}

//set the payload for a state, set expiration, do gc as needed
func (oclient *Oclient) setState() {
	PkceInit()
	mutex.Lock()
	oclient.State = &State{
		CreatedAt:    time.Now().UTC(),
		PkceVerifier: PkceVerifier(128),
	}
	defer mutex.Unlock()
	return
}

//== Cookie Helpers

const CookiePrefix = "_oclient"

func cookieName(service string) string {
	return (CookiePrefix + service)
}

//generic cookie setter
func setCookie(w http.ResponseWriter, token string, cookieName string) {
	tok64 := base64.StdEncoding.EncodeToString([]byte(token))
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    tok64,
		HttpOnly: true,
		Secure:   false, //use true for production
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	return
}

//generic cookie getter
func getCookie(r *http.Request, cookieName string) (token string, err error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	tokb, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return
	}
	token = string(tokb)
	return
}

//== API Helpers

//build service Code Authorize Link and save state as pkceVerifier (128)
func AuthLink(r *http.Request, authtype string, service string) (result string) {
	stData := State{Service: service, AuthType: authtype}
	st := PkceVerifier(128)
	result = services[service]["authorize_endpoint"]
	result += "?client_id=" + services[service]["client_id"]
	result += "&response_type=code&redirect_uri="
	result += url.QueryEscape(services[service]["redirect_uri"])
	result += "&scope=" + services[service]["scope"]
	result += services[service]["prompt"]
	if authtype == PKCE {
		stData.PkceVerifier = PkceVerifier(128)
		stData.PkceChallenge = PkceChallenge(stData.PkceVerifier)
		result += "&code_challenge=" + stData.PkceChallenge
		result += "&code_challenge_method=S256"
	}
	result += "&state=" + st
	setState(st, &stData)
	fmt.Println("Debug Authorize Link: ", result)
	return
}

//make call to a resource api, add oauth bearer token
func ApiRequest(w http.ResponseWriter, r *http.Request, service, method, url string, data map[string]interface{}) (response *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	var body io.Reader
	if data == nil {
		body = nil
	} else {
		var requestBody []byte
		requestBody, err = json.Marshal(data)
		if err != nil {
			return
		}
		body = bytes.NewBuffer(requestBody)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	err = setHeader(w, r, service, request)
	if err != nil {
		err = errors.New("Unable to set Header: " + err.Error())
		return
	}
	response, err = client.Do(request)
	return
}

func epochSeconds() int64 {
	now := time.Now()
	secs := now.Unix()
	return secs
}

//get Access Token via cookie, refresh if expired, set header bearer token
func setHeader(w http.ResponseWriter, r *http.Request, service string, newReq *http.Request) (err error) {
	token, err := getCookie(r, cookieName(service))
	if err != nil {
		return
	}
	var tokMap map[string]interface{}

	// err = json.Unmarshal([]byte(token), &tokMap)
	// normally as above, but we want numbers as ints vs floats
	decoder := json.NewDecoder(strings.NewReader(token))
	decoder.UseNumber()
	err = decoder.Decode(&tokMap)

	expiresAt, err := tokMap["expires_at"].(json.Number).Int64()
	if err != nil {
		return
	}
	if epochSeconds() > expiresAt { //token has expired, refresh it
		if services[service]["refresh_allowed"] == "false" {
			err = errors.New("Non-refreshable Token Expired, Re-authorize")
			return
		}
		refresh, exists := tokMap["refresh_token"]
		if !exists {
			err = errors.New("Refresh Token Not Found")
			return
		}
		var newToken string
		newToken, err = getToken(w, r, service, REFRESH, refresh.(string), SECRET, "")
		if err != nil {
			return
		}
		setCookie(w, newToken, cookieName(service)) //note: must set cookie before writing to responsewriter
		decoder = json.NewDecoder(strings.NewReader(newToken))
		decoder.UseNumber()
		tokMap = make(map[string]interface{})
		err = decoder.Decode(&tokMap)
		if err != nil {
			return
		}
	}
	newReq.Header.Add("Authorization", "Bearer "+tokMap["access_token"].(string))
	newReq.Header.Set("Content-Type", "application/json")
	newReq.Header.Set("Accept", "application/json")
	return
}

//== Access Token

//exchange the Authorization Code for Access Token
func ExchangeCode(w http.ResponseWriter, r *http.Request, code string, state string) (err error) {
	statePtr := getState(state)
	if statePtr == nil {
		err = errors.New("State Key not found")
		return
	}
	token, err := getToken(w, r, statePtr.Service, AUTHORIZE, code, statePtr.AuthType, statePtr.PkceVerifier)
	if err != nil {
		return
	}
	setCookie(w, token, cookieName(statePtr.Service)) //note: must set cookie before writing to responsewriter
	return
}

//wrapper to set accept header
func jsonPost(url string, body io.Reader) (resp *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func basicPost(url string, body io.Reader, ba string) (resp *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Basic "+ba)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

//subtract a small delta from exires_at to account for transport time
const DELTASECS = 5

//get a token from authorization endpoint
func getToken(w http.ResponseWriter, r *http.Request, service string, tokType string, code string, authType string, verifier string) (result string, err error) {
	rParams := map[string]string{
		"client_id":    services[service]["client_id"],
		"redirect_uri": services[service]["redirect_uri"],
	}
	switch tokType {
	case AUTHORIZE:
		rParams["code"] = code
		rParams["grant_type"] = AUTHORIZE
	case REFRESH:
		rParams["refresh_token"] = code
		rParams["grant_type"] = REFRESH
	default:
		err = errors.New("Unknown tokType")
		return
	}
	switch authType {
	case SECRET:
		rParams["client_secret"] = services[service]["client_secret"]
	case PKCE:
		rParams["code_verifier"] = verifier
	default:
		err = errors.New("Unknown authType")
		return
	}
	var resp *http.Response
	switch services[service]["post_type"] {
	case "basic":
		form := url.Values{}
		for k, v := range rParams {
			form.Set(k, v)
		}

		basic := basicAuth(rParams["client_id"], rParams["client_secret"])

		resp, err = basicPost(services[service]["token_endpoint"], strings.NewReader(form.Encode()), basic)
		if err != nil {
			return
		}
	case "json":
		var requestBody []byte
		requestBody, err = json.Marshal(rParams)
		if err != nil {
			return
		}
		resp, err = jsonPost(services[service]["token_endpoint"], bytes.NewBuffer(requestBody))
		if err != nil {
			return
		}

	case "form":
		vals := url.Values{}
		for k, v := range rParams {
			vals.Set(k, v)
		}
		resp, err = http.PostForm(services[service]["token_endpoint"], vals)
		if err != nil {
			return
		}
	default:
		err = errors.New("Unknown post_type")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(string(body))
		return
	}
	//check for expires_at
	var tokMap map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	err = decoder.Decode(&tokMap)
	if err != nil {
		err = errors.New("decoder.Decode: " + err.Error())
		return
	}
	expire, exists := tokMap["expires_at"]

	if exists {
		result = string(body)
		return
	}
	var expiresIn int64
	expire, exists = tokMap["expires_in"]
	if !exists { //no expiration, so make it a year
		expiresIn = 31536000
	} else {
		expiresIn, err = expire.(json.Number).Int64()
	}
	tokMap["expires_at"] = epochSeconds() + expiresIn - DELTASECS
	b, err := json.Marshal(tokMap)
	if err != nil {
		err = errors.New("json.Marshal: " + err.Error())
		return
	}
	result = string(b)
	return
}
