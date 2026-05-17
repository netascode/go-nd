// Package nd is a Cisco Nexus Dashboard REST client library for Go.
package nd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const DefaultMaxRetries int = 3
const DefaultBackoffMinDelay int = 2
const DefaultBackoffMaxDelay int = 60
const DefaultBackoffDelayFactor float64 = 3

// Client is an HTTP Nexus Dashboard client.
// Use nd.NewClient to initiate a client.
// This will ensure proper cookie handling and processing of modifiers.
type Client struct {
	// HttpClient is the *http.Client used for API requests.
	HttpClient *http.Client
	// Url is the Nexus Dashboard IP or hostname, e.g. https://10.0.0.1:443 (port is optional).
	Url string
	// BasePath is the Nexus Dashboard URL prefix to use, e.g. '/appcenter/cisco/ndfc/api/v1'.
	BasePath string
	// Token is the current authentication token
	Token string
	// Usr is the Nexus Dashboard username.
	Usr string
	// Pwd is the Nexus Dashboard password.
	Pwd string
	// ApiKey is the Nexus Dashboard user API key (alternative to password-based auth).
	// When set, requests use X-Nd-Username and X-Nd-Apikey headers instead of JWT Bearer tokens.
	ApiKey string
	// authBasePath is the auto-detected URL prefix for authentication endpoints (login, logout, refresh).
	// Set automatically on first login by trying /api/v1/infra (4.2.1+) first, then falling back to "".
	authBasePath string
	// authDetected indicates whether the auth endpoint has been discovered.
	authDetected bool
	// Domain is the Nexus Dashboard domain.
	Domain string
	// Insecure determines if insecure https connections are allowed.
	Insecure bool
	// Maximum number of retries
	MaxRetries int
	// Minimum delay between two retries
	BackoffMinDelay int
	// Maximum delay between two retries
	BackoffMaxDelay int
	// Backoff delay factor
	BackoffDelayFactor float64
	// Authentication mutex
	AuthenticationMutex *sync.Mutex
	// Authentication timestamp
	AuthTimeStamp time.Time
	// Authentication token timeout
	AuthTokenTimeout time.Duration
}

// NewClient creates a new Nexus Dashboard HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("https://10.1.1.1", "/appcenter/cisco/ndfc/api/v1", "user", "password", "", true, RequestTimeout(120))
func NewClient(url, basePath, usr, pwd, domain string, insecure bool, mods ...func(*Client)) (Client, error) {
	// Configure TCP dial timeout (default 120 seconds to avoid OS 2-minute timeout)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		DialContext: (&net.Dialer{
			Timeout:   120 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 30 * time.Second,
	}

	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
		Jar:       cookieJar,
	}

	if domain == "" {
		domain = "DefaultAuth"
	}

	client := Client{
		HttpClient:          &httpClient,
		Url:                 url,
		BasePath:            basePath,
		Usr:                 usr,
		Pwd:                 pwd,
		Domain:              domain,
		Insecure:            insecure,
		MaxRetries:          DefaultMaxRetries,
		BackoffMinDelay:     DefaultBackoffMinDelay,
		BackoffMaxDelay:     DefaultBackoffMaxDelay,
		BackoffDelayFactor:  DefaultBackoffDelayFactor,
		AuthenticationMutex: &sync.Mutex{},
		AuthTokenTimeout:    0,
	}

	for _, mod := range mods {
		mod(&client)
	}

	return client, nil
}

// RequestTimeout modifies the HTTP request timeout from the default of 60 seconds.
func RequestTimeout(x time.Duration) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Timeout = x * time.Second
		// Update TCP dial timeout if total timeout is >= 2 minutes
		// to avoid OS-level TCP timeout interfering with longer request timeouts
		if x >= 120 {
			if transport, ok := client.HttpClient.Transport.(*http.Transport); ok {
				transport.DialContext = (&net.Dialer{
					Timeout:   x * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext
			}
		}
	}
}

// MaxRetries modifies the maximum number of retries from the default of 3.
func MaxRetries(x int) func(*Client) {
	return func(client *Client) {
		client.MaxRetries = x
	}
}

// BackoffMinDelay modifies the minimum delay between two retries from the default of 2.
func BackoffMinDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMinDelay = x
	}
}

// BackoffMaxDelay modifies the maximum delay between two retries from the default of 60.
func BackoffMaxDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMaxDelay = x
	}
}

// BackoffDelayFactor modifies the backoff delay factor from the default of 3.
func BackoffDelayFactor(x float64) func(*Client) {
	return func(client *Client) {
		client.BackoffDelayFactor = x
	}
}

// UserApiKey sets API key authentication.
// When set, the client uses X-Nd-Username and X-Nd-Apikey in the header
// instead of JWT Bearer token authentication. No login or refresh is needed.
func UserApiKey(x string) func(*Client) {
	return func(client *Client) {
		client.ApiKey = x
	}
}

// NewReq creates a new Req request for this client.
func (client Client) NewReq(method, uri string, body io.Reader, mods ...func(*Req)) Req {
	httpReq, _ := http.NewRequest(method, client.Url+uri, body)
	httpReq.Header.Add("Content-Type", "application/json")
	req := Req{
		HttpReq:    httpReq,
		LogPayload: true,
	}
	for _, mod := range mods {
		mod(&req)
	}
	return req
}

// Do makes a request and returns the GJSON result.
// Requests for Do are built ouside of the client, e.g.
//
//	req := client.NewReq("GET", "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics", nil)
//	res, _ := client.Do(req)
func (client *Client) Do(req Req) (Res, error) {
	var res Res
	defer log.Printf("[DEBUG] Exit from Do method")
	bodyBytes, err := client.doReq(req)
	// Look for response message in case of error also
	if len(bodyBytes) > 0 {
		if !json.Valid(bodyBytes) {
			res = Res(gjson.Parse(`{"response": "` + string(bodyBytes) + `"}`))
		} else {
			res = Res(gjson.ParseBytes(bodyBytes))
		}
	}
	if err != nil {
		return res, err
	}
	if req.LogPayload {
		log.Printf("[DEBUG] HTTP Response: %s", res)
	}
	return res, nil
}

// DoRaw makes a request and returns the raw response (bytes).
func (client *Client) DoRaw(req Req) ([]byte, error) {
	defer log.Printf("[DEBUG] Exit from DoRaw method")
	bodyBytes, err := client.doReq(req)
	if err != nil {
		return bodyBytes, err
	}
	if req.LogPayload {
		log.Printf("[DEBUG] HTTP Response: %s", string(bodyBytes))
	}
	return bodyBytes, nil
}

func (client *Client) doReq(req Req) ([]byte, error) {
	// retain the request body across multiple attempts
	var body []byte
	if req.HttpReq.Body != nil {
		body, _ = io.ReadAll(req.HttpReq.Body)
	}
	var bodyBytes []byte
	defer log.Printf("[DEBUG] Exit from doReq method")
	for attempts := 0; ; attempts++ {
		// Set auth headers inside loop to pick up refreshed tokens after re-authentication
		if client.ApiKey != "" {
			req.HttpReq.Header.Set("X-Nd-Username", client.Usr)
			req.HttpReq.Header.Set("X-Nd-Apikey", client.ApiKey)
			req.HttpReq.Header.Del("Authorization")
		} else {
			req.HttpReq.Header.Set("Authorization", "Bearer "+client.Token)
		}
		req.HttpReq.Body = io.NopCloser(bytes.NewBuffer(body))
		if req.LogPayload {
			log.Printf("[DEBUG] HTTP Request: %s, |%s|, |%s|", req.HttpReq.Method, req.HttpReq.URL, req.HttpReq.Body)
		} else {
			log.Printf("[DEBUG] HTTP Request: %s, %s", req.HttpReq.Method, req.HttpReq.URL)
		}

		httpRes, err := client.HttpClient.Do(req.HttpReq)
		if err != nil {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] HTTP Connection error occured: %+v", err)
				return nil, err
			} else {
				log.Printf("[ERROR] HTTP Connection failed: %q, retries: %v", err, attempts)
				continue
			}
		}

		defer httpRes.Body.Close()
		bodyBytes, err = io.ReadAll(httpRes.Body)
		if err != nil {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] Cannot decode response body: %+v", err)
				return nil, err
			} else {
				log.Printf("[ERROR] Cannot decode response body: %s, retries: %v", err, attempts)
				continue
			}
		}

		if httpRes.StatusCode >= 200 && httpRes.StatusCode <= 299 {
			break
		} else {
			if ok := client.Backoff(attempts); !ok {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				return bodyBytes, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			} else if httpRes.StatusCode == 408 || (httpRes.StatusCode >= 501 && httpRes.StatusCode <= 599) {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v, Retries: %v", httpRes.StatusCode, attempts)
				continue
			} else if httpRes.StatusCode == 401 && strings.Contains(string(bodyBytes), "token has expired") {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v, Retries: %v", httpRes.StatusCode, attempts)
				if client.ApiKey != "" {
					// API key auth does not support re-authentication
					log.Printf("[ERROR] API key authentication failed (401)")
					return bodyBytes, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				}
				client.Token = ""
				err := client.Authenticate()
				if err != nil {
					log.Printf("[ERROR] Authentication failed: StatusCode %v, Retries: %v", httpRes.StatusCode, attempts)
					return bodyBytes, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				}
			} else {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v", httpRes.StatusCode)
				return bodyBytes, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			}
		}
	}

	return bodyBytes, nil
}

// Get makes a GET request and returns a GJSON result.
// Results will be the raw data structure as returned by Nexus Dashboard
func (client *Client) Get(path string, mods ...func(*Req)) (Res, error) {
	req := client.NewReq("GET", client.BasePath+path, nil, mods...)
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// GetRawJson makes a GET request and returns the raw response (bytes).
// Results will be the raw data structure as returned by Nexus Dashboard
func (client *Client) GetRawJson(path string, mods ...func(*Req)) ([]byte, error) {
	req := client.NewReq("GET", client.BasePath+path, nil, mods...)
	err := client.Authenticate()
	if err != nil {
		return nil, err
	}
	return client.DoRaw(req)
}

// Delete makes a DELETE request and returns a GJSON result.
// Hint: Use the Body struct to easily create DELETE body data.
func (client *Client) Delete(path string, data string, mods ...func(*Req)) (Res, error) {
	req := client.NewReq("DELETE", client.BasePath+path, strings.NewReader(data), mods...)
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Post makes a POST request and returns a GJSON result.
// Hint: Use the Body struct to easily create POST body data.
func (client *Client) Post(path, data string, mods ...func(*Req)) (Res, error) {
	req := client.NewReq("POST", client.BasePath+path, strings.NewReader(data), mods...)
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Put makes a PUT request and returns a GJSON result.
// Hint: Use the Body struct to easily create PUT body data.
func (client *Client) Put(path, data string, mods ...func(*Req)) (Res, error) {
	req := client.NewReq("PUT", client.BasePath+path, strings.NewReader(data), mods...)
	err := client.Authenticate()
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Login handles authentication to Nexus Dashboard.
// On the first call, Login auto-detects the correct endpoint by trying
// /api/v1/infra/login (4.2.1+) first. If that returns a non-200 status,
// it falls back to /login (pre-4.2.1). The discovered path is cached for
// subsequent calls.
func (client *Client) Login() error {
	body := ""
	body, _ = sjson.Set(body, "userName", client.Usr)
	body, _ = sjson.Set(body, "userPasswd", client.Pwd)
	body, _ = sjson.Set(body, "domain", client.Domain)

	if client.authDetected {
		// Path already discovered — use it directly
		return client.doLogin(client.authBasePath+"/login", body)
	}

	// Auto-detect: try 4.2.1+ endpoint first
	log.Printf("[DEBUG] Auto-detecting auth endpoint...")
	err := client.doLogin("/api/v1/infra/login", body)
	if err == nil {
		client.authBasePath = "/api/v1/infra"
		client.authDetected = true
		log.Printf("[DEBUG] Auto-detected auth endpoint: /api/v1/infra")
		return nil
	}

	// Fall back to legacy endpoint
	log.Printf("[DEBUG] New auth endpoint not available, falling back to /login")
	err = client.doLogin("/login", body)
	if err == nil {
		client.authBasePath = ""
		client.authDetected = true
		log.Printf("[DEBUG] Auto-detected auth endpoint: /login (legacy)")
	}
	return err
}

// doLogin performs the actual login HTTP request to the given path.
func (client *Client) doLogin(path, body string) error {
	req := client.NewReq("POST", path, strings.NewReader(body), NoLogPayload)
	log.Printf("[TRACE] Client Login: starting http request to %s", path)
	httpRes, err := client.HttpClient.Do(req.HttpReq)
	if err != nil {
		log.Printf("[ERROR] Client Login: HTTP request failed - %v", err)
		return err
	}
	defer httpRes.Body.Close()
	if httpRes.StatusCode != 200 {
		log.Printf("[ERROR] Authentication failed at %s: StatusCode %v", path, httpRes.StatusCode)
		return fmt.Errorf("Authentication failed")
	}
	bodyBytes, _ := io.ReadAll(httpRes.Body)
	res := Res(gjson.ParseBytes(bodyBytes))
	token := res.Get("jwttoken").String()
	if token == "" {
		token = res.Get("token").String()
	}
	if token == "" {
		log.Printf("[ERROR] Token retrieval failed: no token in payload")
		return fmt.Errorf("Authentication failed")
	}
	client.Token = token
	client.AuthTimeStamp = time.Now()
	log.Printf("[DEBUG] Authentication successful via %s", path)
	return nil
}

// Refresh attempts to refresh the current JWT token using the 4.2.1+ /refresh endpoint.
// Returns an error if the endpoint is not available (pre-4.2.1) or the refresh fails.
func (client *Client) Refresh() error {
	body := ""
	body, _ = sjson.Set(body, "jwttoken", client.Token)
	req := client.NewReq("POST", client.authBasePath+"/refresh", strings.NewReader(body), NoLogPayload)
	log.Printf("[TRACE] Client Refresh: starting http request")
	httpRes, err := client.HttpClient.Do(req.HttpReq)
	if err != nil {
		log.Printf("[ERROR] Client Refresh: HTTP request failed - %v", err)
		return err
	}
	defer httpRes.Body.Close()
	if httpRes.StatusCode != 200 {
		log.Printf("[DEBUG] Token refresh failed: StatusCode %v (endpoint may not be available)", httpRes.StatusCode)
		return fmt.Errorf("Token refresh failed: StatusCode %v", httpRes.StatusCode)
	}
	bodyBytes, _ := io.ReadAll(httpRes.Body)
	res := Res(gjson.ParseBytes(bodyBytes))
	token := res.Get("jwttoken").String()
	if token == "" {
		token = res.Get("token").String()
	}
	if token == "" {
		log.Printf("[ERROR] Token refresh failed: no token in payload")
		return fmt.Errorf("Token refresh failed")
	}
	client.Token = token
	client.AuthTimeStamp = time.Now()
	log.Printf("[DEBUG] Token refresh successful")
	return nil
}

// Logout terminates the current session using the 4.2.1+ /logout endpoint.
// Returns an error if the endpoint is not available (pre-4.2.1) or the logout fails.
// This is a no-op when using API key authentication.
func (client *Client) Logout() error {
	if client.ApiKey != "" {
		log.Printf("[DEBUG] Logout skipped: using API key authentication")
		return nil
	}
	if client.Token == "" {
		log.Printf("[DEBUG] Logout skipped: no active token")
		return nil
	}
	req := client.NewReq("POST", client.authBasePath+"/logout", nil, NoLogPayload)
	req.HttpReq.Header.Set("Authorization", "Bearer "+client.Token)
	log.Printf("[TRACE] Client Logout: starting http request")
	httpRes, err := client.HttpClient.Do(req.HttpReq)
	if err != nil {
		log.Printf("[ERROR] Client Logout: HTTP request failed - %v", err)
		return err
	}
	defer httpRes.Body.Close()
	if httpRes.StatusCode != 200 {
		log.Printf("[DEBUG] Logout failed: StatusCode %v (endpoint may not be available)", httpRes.StatusCode)
		return fmt.Errorf("Logout failed: StatusCode %v", httpRes.StatusCode)
	}
	client.Token = ""
	log.Printf("[DEBUG] Logout successful")
	return nil
}

func (client *Client) checkAndFillTokenTimeout() {
	req := client.NewReq("GET", "/api/config/dn/apigwcfg/default", nil, NoLogPayload)
	result, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Get API Config: %v", err)
		return
	}
	/* Response Format
			{
			"config": {
				"idle_session_timeout_sec": 3600,
				"jwt_session_timeout_sec": 1200,
				"log_level": "info"
			},
	    }
	*/
	tokenTimeout := result.Get("config.jwt_session_timeout_sec").Int()
	if tokenTimeout > 0 {
		client.AuthTokenTimeout = (time.Duration(tokenTimeout/2) * time.Second)
		log.Printf("[INFO] Token timeout set to %v", client.AuthTokenTimeout)
		return
	}
	client.AuthTokenTimeout = 2 * time.Minute
	log.Printf("[ERROR] Token timeout could not be read %v, using default value", result)
}

// Authenticate ensures the client has a valid authentication state.
// For API key auth: no-op (API key is sent per-request via headers).
// For JWT auth: logs in if no token, attempts refresh if token is expiring
// (falling back to full login if refresh fails or is unavailable on pre-4.2.1).
func (client *Client) Authenticate() error {
	// API key auth requires no login/refresh
	if client.ApiKey != "" {
		log.Printf("[TRACE] Using API key authentication, skipping login")
		return nil
	}

	var err error
	log.Printf("[TRACE] Attempting authentication...")
	client.AuthenticationMutex.Lock()
	if client.Token == "" {
		log.Printf("[DEBUG] No token available, attempting login...")
		err = client.Login()
		if err == nil {
			client.checkAndFillTokenTimeout()
		}
	} else if time.Since(client.AuthTimeStamp) > client.AuthTokenTimeout {
		log.Printf("[DEBUG] Token approaching expiry, attempting refresh...")
		err = client.Refresh()
		if err != nil {
			// Refresh failed (pre-4.2.1 or other error), fall back to full login
			log.Printf("[DEBUG] Refresh failed, falling back to login...")
			err = client.Login()
			if err == nil {
				client.checkAndFillTokenTimeout()
			}
		}
	}
	log.Printf("[TRACE] Authentication complete")
	client.AuthenticationMutex.Unlock()
	return err
}

// Backoff waits following an exponential backoff algorithm
func (client *Client) Backoff(attempts int) bool {
	log.Printf("[DEBUG] Begining backoff method: attempts %v on %v", attempts, client.MaxRetries)
	if attempts >= client.MaxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	minDelay := time.Duration(client.BackoffMinDelay) * time.Second
	maxDelay := time.Duration(client.BackoffMaxDelay) * time.Second

	min := float64(minDelay)
	backoff := min * math.Pow(client.BackoffDelayFactor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))
	time.Sleep(backoffDuration)
	log.Printf("[DEBUG] Exit from backoff method with return value true")
	return true
}
