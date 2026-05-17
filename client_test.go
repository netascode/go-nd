package nd

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

const (
	testURL = "https://10.0.0.1"
)

func testClient() Client {
	client, _ := NewClient(testURL, "/", "usr", "pwd", "", true, MaxRetries(0))
	client.authDetected = true // skip auto-detection in most tests
	gock.InterceptClient(client.HttpClient)
	return client
}

func authenticatedTestClient() Client {
	client := testClient()
	client.Token = "ABC"
	client.AuthTimeStamp = time.Now()
	client.AuthTokenTimeout = 2 * time.Minute
	return client
}

func apiKeyTestClient() Client {
	client, _ := NewClient(testURL, "/", "usr", "", "", true, MaxRetries(0), UserApiKey("my-api-key"))
	client.authDetected = true
	gock.InterceptClient(client.HttpClient)
	return client
}

// ErrReader implements the io.Reader interface and fails on Read.
type ErrReader struct{}

// Read mocks failing io.Reader test cases.
func (r ErrReader) Read(buf []byte) (int, error) {
	return 0, errors.New("fail")
}

// TestNewClient tests the NewClient function.
func TestNewClient(t *testing.T) {
	client, _ := NewClient(testURL, "/", "usr", "pwd", "", true, RequestTimeout(120))
	assert.Equal(t, client.HttpClient.Timeout, 120*time.Second)
}

// TestClientLogin tests the Client::Login method.
func TestClientLogin(t *testing.T) {
	defer gock.Off()
	client := testClient()

	// Successful login with legacy token field
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"token": "ABC"}`)
	assert.NoError(t, client.Login())
	assert.Equal(t, "ABC", client.Token)

	// Successful login with 4.2.1+ jwttoken field (preferred over token)
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"jwttoken": "JWT123", "token": "COMPAT"}`)
	assert.NoError(t, client.Login())
	assert.Equal(t, "JWT123", client.Token)

	// Successful login with only jwttoken field
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"jwttoken": "JWT456"}`)
	assert.NoError(t, client.Login())
	assert.Equal(t, "JWT456", client.Token)

	// Unsuccessful token retrieval
	gock.New(testURL).Post("/login").Reply(200).BodyString("")
	assert.Error(t, client.Login())

	// Invalid HTTP status code
	gock.New(testURL).Post("/login").Reply(405)
	assert.Error(t, client.Login())
}

// TestClientGet tests the Client::Get method.
func TestClientGet(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()
	var err error

	// Success
	gock.New(testURL).Get("/url").Reply(200)
	_, err = client.Get("/url")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Get("/url").ReplyError(errors.New("fail"))
	_, err = client.Get("/url")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Get("/url").Reply(405)
	_, err = client.Get("/url")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Get("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Get("/url")
	assert.Error(t, err)
}

// TestClientDelete tests the Client::Delete method.
func TestClientDelete(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Success
	gock.New(testURL).
		Delete("/url").
		Reply(200)
	_, err := client.Delete("/url", "")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).
		Delete("/url").
		ReplyError(errors.New("fail"))
	_, err = client.Delete("/url", "")
	assert.Error(t, err)
}

// TestClientPost tests the Client::Post method.
func TestClientPost(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	var err error

	// Success
	gock.New(testURL).Post("/url").Reply(200)
	_, err = client.Post("/url", "{}")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Post("/url").ReplyError(errors.New("fail"))
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Post("/url").Reply(405)
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Post("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Post("/url", "{}")
	assert.Error(t, err)
}

// TestClientPut tests the Client::Put method.
func TestClientPut(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	var err error

	// Success
	gock.New(testURL).Put("/url").Reply(200)
	_, err = client.Put("/url", "{}")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Put("/url").ReplyError(errors.New("fail"))
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Put("/url").Reply(405)
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Put("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.Put("/url", "{}")
	assert.Error(t, err)
}

// TestClientGetRawJson tests the Client::GetRawJson method.
func TestClientGetRawJson(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()
	var err error

	// Success
	gock.New(testURL).Get("/url").Reply(200)
	_, err = client.GetRawJson("/url")
	assert.NoError(t, err)

	// HTTP error
	gock.New(testURL).Get("/url").ReplyError(errors.New("fail"))
	_, err = client.GetRawJson("/url")
	assert.Error(t, err)

	// Invalid HTTP status code
	gock.New(testURL).Get("/url").Reply(405)
	_, err = client.GetRawJson("/url")
	assert.Error(t, err)

	// Error decoding response body
	gock.New(testURL).
		Get("/url").
		Reply(200).
		Map(func(res *http.Response) *http.Response {
			res.Body = io.NopCloser(ErrReader{})
			return res
		})
	_, err = client.GetRawJson("/url")
	assert.Error(t, err)
}

// TestClientRefresh tests the Client::Refresh method.
func TestClientRefresh(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Successful refresh with jwttoken field
	gock.New(testURL).Post("/refresh").Reply(200).BodyString(`{"jwttoken": "REFRESHED"}`)
	assert.NoError(t, client.Refresh())
	assert.Equal(t, "REFRESHED", client.Token)

	// Successful refresh with legacy token field
	gock.New(testURL).Post("/refresh").Reply(200).BodyString(`{"token": "REFRESHED2"}`)
	assert.NoError(t, client.Refresh())
	assert.Equal(t, "REFRESHED2", client.Token)

	// Refresh endpoint not available (pre-4.2.1)
	gock.New(testURL).Post("/refresh").Reply(404)
	assert.Error(t, client.Refresh())

	// Refresh returns empty token
	gock.New(testURL).Post("/refresh").Reply(200).BodyString(`{}`)
	assert.Error(t, client.Refresh())

	// Refresh HTTP error
	gock.New(testURL).Post("/refresh").ReplyError(errors.New("fail"))
	assert.Error(t, client.Refresh())
}

// TestClientLogout tests the Client::Logout method.
func TestClientLogout(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// Successful logout
	gock.New(testURL).Post("/logout").Reply(200)
	assert.NoError(t, client.Logout())
	assert.Equal(t, "", client.Token)

	// Logout with no active token (no-op)
	client.Token = ""
	assert.NoError(t, client.Logout())

	// Logout skipped with API key
	client.ApiKey = "some-key"
	assert.NoError(t, client.Logout())
	client.ApiKey = ""

	// Logout endpoint not available (pre-4.2.1)
	client.Token = "ABC"
	gock.New(testURL).Post("/logout").Reply(404)
	assert.Error(t, client.Logout())

	// Logout HTTP error
	client.Token = "ABC"
	gock.New(testURL).Post("/logout").ReplyError(errors.New("fail"))
	assert.Error(t, client.Logout())
}

// TestClientAuthenticateRefreshFallback tests that Authenticate prefers refresh over login.
func TestClientAuthenticateRefreshFallback(t *testing.T) {
	defer gock.Off()
	client := testClient()
	client.Token = "OLD"
	client.AuthTimeStamp = time.Now().Add(-10 * time.Minute)
	client.AuthTokenTimeout = 1 * time.Minute

	// Refresh succeeds — no login needed
	gock.New(testURL).Post("/refresh").Reply(200).BodyString(`{"jwttoken": "REFRESHED"}`)
	assert.NoError(t, client.Authenticate())
	assert.Equal(t, "REFRESHED", client.Token)

	// Refresh fails — falls back to login
	client.Token = "OLD"
	client.AuthTimeStamp = time.Now().Add(-10 * time.Minute)
	gock.New(testURL).Post("/refresh").Reply(404)
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"jwttoken": "LOGGEDIN"}`)
	gock.New(testURL).Get("/api/config/dn/apigwcfg/default").Reply(200).BodyString(`{"config":{"jwt_session_timeout_sec":1200}}`)
	assert.NoError(t, client.Authenticate())
	assert.Equal(t, "LOGGEDIN", client.Token)
}

// TestClientApiKeyAuth tests API key authentication flow.
func TestClientApiKeyAuth(t *testing.T) {
	defer gock.Off()
	client := apiKeyTestClient()

	// Authenticate is a no-op with API key
	assert.NoError(t, client.Authenticate())

	// GET request uses API key headers
	gock.New(testURL).
		Get("/url").
		MatchHeader("X-Nd-Username", "usr").
		MatchHeader("X-Nd-Apikey", "my-api-key").
		Reply(200).
		BodyString(`{"result": "ok"}`)
	res, err := client.Get("/url")
	assert.NoError(t, err)
	assert.Equal(t, "ok", res.Get("result").String())

	// POST request uses API key headers
	gock.New(testURL).
		Post("/url").
		MatchHeader("X-Nd-Username", "usr").
		MatchHeader("X-Nd-Apikey", "my-api-key").
		Reply(200).
		BodyString(`{"result": "created"}`)
	res, err = client.Post("/url", `{"name":"test"}`)
	assert.NoError(t, err)
	assert.Equal(t, "created", res.Get("result").String())
}

// TestNewClientApiKeyOption tests the UserApiKey functional option.
func TestNewClientApiKeyOption(t *testing.T) {
	client, err := NewClient(testURL, "/", "usr", "", "", true, UserApiKey("test-key"))
	assert.NoError(t, err)
	assert.Equal(t, "test-key", client.ApiKey)
	assert.Equal(t, "usr", client.Usr)
}

// TestLoginAutoDetect tests auto-detection of the auth endpoint.
func TestLoginAutoDetect(t *testing.T) {
	defer gock.Off()

	// Auto-detect: 4.2.1+ endpoint available — uses it and caches the path
	clientNew, _ := NewClient(testURL, "/", "usr", "pwd", "", true, MaxRetries(0))
	gock.InterceptClient(clientNew.HttpClient)
	gock.New(testURL).Post("/api/v1/infra/login").Reply(200).BodyString(`{"jwttoken": "TOKEN_421"}`)
	assert.NoError(t, clientNew.Login())
	assert.Equal(t, "TOKEN_421", clientNew.Token)
	assert.Equal(t, "/api/v1/infra", clientNew.authBasePath)
	assert.True(t, clientNew.authDetected)

	// Second login reuses cached path (no auto-detect probe)
	gock.New(testURL).Post("/api/v1/infra/login").Reply(200).BodyString(`{"jwttoken": "TOKEN_421_2"}`)
	assert.NoError(t, clientNew.Login())
	assert.Equal(t, "TOKEN_421_2", clientNew.Token)

	// Auto-detect: 4.2.1+ endpoint not available — falls back to /login
	clientOld, _ := NewClient(testURL, "/", "usr", "pwd", "", true, MaxRetries(0))
	gock.InterceptClient(clientOld.HttpClient)
	gock.New(testURL).Post("/api/v1/infra/login").Reply(404)
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"token": "TOKEN_OLD"}`)
	assert.NoError(t, clientOld.Login())
	assert.Equal(t, "TOKEN_OLD", clientOld.Token)
	assert.Equal(t, "", clientOld.authBasePath)
	assert.True(t, clientOld.authDetected)

	// Second login reuses cached legacy path
	gock.New(testURL).Post("/login").Reply(200).BodyString(`{"token": "TOKEN_OLD_2"}`)
	assert.NoError(t, clientOld.Login())
	assert.Equal(t, "TOKEN_OLD_2", clientOld.Token)

	// Auto-detect: both endpoints fail — returns error
	clientFail, _ := NewClient(testURL, "/", "usr", "pwd", "", true, MaxRetries(0))
	gock.InterceptClient(clientFail.HttpClient)
	gock.New(testURL).Post("/api/v1/infra/login").Reply(404)
	gock.New(testURL).Post("/login").Reply(500)
	assert.Error(t, clientFail.Login())
}
