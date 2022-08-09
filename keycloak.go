package keycloak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"cns.bg/gohub/tracing"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Keycloak struct {
	Realm         string
	Address       string
	AdminUsername string
	AdminPassword string
}

func NewKeyloak(realm string, address string, adminUsername string, adminPassword string) *Keycloak {
	return &Keycloak{Realm: realm, Address: address, AdminUsername: adminUsername, AdminPassword: adminPassword}
}

var adminToken *Auth

type Auth struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type Client struct {
	ID                           string   `json:"id,omitempty"`
	ClientID                     string   `json:"clientId,omitempty"`
	RootURL                      string   `json:"rootUrl,omitempty"`
	BaseURL                      string   `json:"baseUrl,omitempty"`
	SurrogateAuthRequired        bool     `json:"surrogateAuthRequired,omitempty"`
	Enabled                      bool     `json:"enabled,omitempty"`
	AlwaysDisplayInConsole       bool     `json:"alwaysDisplayInConsole,omitempty"`
	ClientAuthenticatorType      string   `json:"clientAuthenticatorType,omitempty"`
	RedirectUris                 []string `json:"redirectUris,omitempty"`
	WebOrigins                   []string `json:"webOrigins,omitempty"`
	NotBefore                    int      `json:"notBefore,omitempty"`
	BearerOnly                   bool     `json:"bearerOnly,omitempty"`
	ConsentRequired              bool     `json:"consentRequired,omitempty"`
	StandardFlowEnabled          bool     `json:"standardFlowEnabled,omitempty"`
	ImplicitFlowEnabled          bool     `json:"implicitFlowEnabled,omitempty"`
	DirectAccessGrantsEnabled    bool     `json:"directAccessGrantsEnabled,omitempty"`
	ServiceAccountsEnabled       bool     `json:"serviceAccountsEnabled,omitempty"`
	AuthorizationServicesEnabled bool     `json:"authorizationServicesEnabled,omitempty"`
	PublicClient                 bool     `json:"publicClient,omitempty"`
	FrontchannelLogout           bool     `json:"frontchannelLogout,omitempty"`
	Protocol                     string   `json:"protocol,omitempty"`
	Attributes                   struct {
	} `json:"attributes,omitempty"`
	AuthenticationFlowBindingOverrides struct {
	} `json:"authenticationFlowBindingOverrides,omitempty"`
	FullScopeAllowed          bool `json:"fullScopeAllowed,omitempty"`
	NodeReRegistrationTimeout int  `json:"nodeReRegistrationTimeout,omitempty"`
	ProtocolMappers           []struct {
		ID              string `json:"id,omitempty"`
		Name            string `json:"name,omitempty"`
		Protocol        string `json:"protocol,omitempty"`
		ProtocolMapper  string `json:"protocolMapper,omitempty"`
		ConsentRequired bool   `json:"consentRequired,omitempty"`
		Config          struct {
			UserSessionNote  string `json:"user.session.note,omitempty"`
			IDTokenClaim     string `json:"id.token.claim,omitempty"`
			AccessTokenClaim string `json:"access.token.claim,omitempty"`
			ClaimName        string `json:"claim.name,omitempty"`
			JSONTypeLabel    string `json:"jsonType.label,omitempty"`
		} `json:"config,omitempty"`
	} `json:"protocolMappers,omitempty"`
	DefaultClientScopes  []string `json:"defaultClientScopes,omitempty"`
	OptionalClientScopes []string `json:"optionalClientScopes,omitempty"`
	Access               struct {
		View      bool `json:"view,omitempty"`
		Configure bool `json:"configure,omitempty"`
		Manage    bool `json:"manage,omitempty"`
	} `json:"access,omitempty"`
}

type ClientSecret struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (k *Keycloak) Authorize(ctx *gin.Context, data url.Values, r *string) (*Auth, error) {
	realm := ""
	if r == nil || *r == "" {
		realm = k.Realm
	} else {
		realm = *r
	}

	endpoint := k.Address + "auth/realms/" + realm + "/protocol/openid-connect/token"

	req, err := http.NewRequestWithContext(ctx.Request.Context(), http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	client := &http.Client{
		Transport: otelhttp.NewTransport(tracing.NewTraceResponseBodyTransport(tracing.NewTraceResponseBodyTransport(http.DefaultTransport)), otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return ctx.FullPath()
		})),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err

	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authToken *Auth
	err = json.Unmarshal(body, &authToken)
	if err != nil {
		return nil, err
	}

	return authToken, nil
}

func (k *Keycloak) AuthorizeClient(ctx *gin.Context, name string, secret string) (*string, error) {

	data := url.Values{}
	data.Add("client_id", name)
	data.Add("client_secret", secret)
	data.Add("grant_type", "client_credentials")
	data.Add("scope", "openid")

	auth, err := k.Authorize(ctx, data, nil)
	if err != nil {
		return nil, err
	}

	return &auth.AccessToken, nil
}

func (k *Keycloak) AuthorizeAdmin(ctx *gin.Context) (*string, error) {

	isExpired := false
	if adminToken != nil {
		keycloakConfig := KeycloakConfig{
			Url: k.Address,
		}

		oauthToken := ExtractTokenFromAuth(adminToken)
		keycloakToken, err := DecodeToken(ctx.Request.Context(), oauthToken, keycloakConfig)
		if err != nil {
			return nil, err
		}

		isExpired = IsExpired(keycloakToken)
	}

	if adminToken == nil || isExpired {
		data := url.Values{}
		data.Add("username", k.AdminUsername)
		data.Add("password", k.AdminPassword)
		data.Add("client_id", "admin-cli")
		data.Add("grant_type", "password")

		realm := "master"

		token, err := k.Authorize(ctx, data, &realm)
		if err != nil {
			return nil, err
		}

		adminToken = token
	}

	return &adminToken.AccessToken, nil
}

func (k *Keycloak) CreateClient(ctx *gin.Context, name string, rootUrl string, baseUrl string) error {

	endpoint := k.Address + "auth/admin/realms/" + k.Realm + "/clients"

	c := &Client{
		ClientID:                     name,
		RootURL:                      rootUrl,
		BaseURL:                      baseUrl,
		RedirectUris:                 []string{"*"},
		WebOrigins:                   []string{"*"},
		DirectAccessGrantsEnabled:    true,
		ServiceAccountsEnabled:       true,
		AuthorizationServicesEnabled: true,
	}

	body, err := json.Marshal(c)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx.Request.Context(), http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	token, err := k.AuthorizeAdmin(ctx)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+*token)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Transport: otelhttp.NewTransport(tracing.NewTraceResponseBodyTransport(tracing.NewTraceResponseBodyTransport(http.DefaultTransport)), otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return ctx.FullPath()
		}))}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("endpoint %s", endpoint)
		fmt.Printf("request %s", string(body))
		fmt.Printf("token %s", *token)

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("response %s", string(bodyBytes))

		return errors.New(fmt.Sprintf("status code is not created but %s", resp.Status))
	}

	return nil
}

func (k *Keycloak) GetClientIdByName(ctx *gin.Context, name string) (*string, error) {
	endpoint := k.Address + "auth/admin/realms/" + k.Realm + "/clients"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		panic(err)
	}

	q := req.URL.Query()
	q.Add("clientId", name)
	rawQuery := q.Encode()
	req.URL.RawQuery = rawQuery

	token, err := k.AuthorizeAdmin(ctx)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+*token)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Transport: otelhttp.NewTransport(tracing.NewTraceResponseBodyTransport(tracing.NewTraceResponseBodyTransport(http.DefaultTransport)), otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return ctx.FullPath()
		})),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("endpoint %s", endpoint)
		fmt.Printf("token %s", *token)
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		fmt.Printf("response %s", string(bodyBytes))
		return nil, errors.New(fmt.Sprintf("status code is not created but %s", resp.Status))
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cs := []Client{}

	err = json.Unmarshal(respBytes, &cs)
	if err != nil {
		return nil, err
	}

	return &cs[0].ID, nil
}

func (k *Keycloak) SetClientSecret(ctx *gin.Context, id string) (*string, error) {
	endpoint := k.Address + "auth/admin/realms/" + k.Realm + "/clients/" + id + "/client-secret"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		panic(err)
	}

	token, err := k.AuthorizeAdmin(ctx)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+*token)

	client := &http.Client{
		Transport: otelhttp.NewTransport(tracing.NewTraceResponseBodyTransport(tracing.NewTraceResponseBodyTransport(http.DefaultTransport)), otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return ctx.FullPath()
		})),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("endpoint %s", endpoint)
		fmt.Printf("token %s", *token)
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		fmt.Printf("response %s", string(bodyBytes))
		return nil, errors.New(fmt.Sprintf("status code is not created but %s", resp.Status))
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	clientSecret := ClientSecret{}

	err = json.Unmarshal(respBytes, &clientSecret)
	if err != nil {
		return nil, err
	}

	return &clientSecret.Value, nil
}
